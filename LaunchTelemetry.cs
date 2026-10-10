// LaunchTelemetry.cs — single-file .NET 8 console app
//
// What it demonstrates (mapped to the job description):
//   - Real-time data processing architecture: UDP ingest -> bounded Channel -> decode -> limit check -> display
//   - Integration of a "device" (the vehicle) into a computer system over a network protocol
//   - CCSDS Space Packet framing (the standard NASA uses for telemetry)
//   - Anomaly detection during a live "launch", with sequence-gap and out-of-limit alarms
// The VehicleSimulator stands in for the launch vehicle. Swap it for a KSP/kRPC or ISS Lightstreamer adapter later.

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

// ----------------------------------------------------------------------------
// 1. Telemetry model
// ----------------------------------------------------------------------------
public readonly record struct TelemetryFrame(
    ushort Apid,
    ushort SequenceCount,
    long MetMillis,          // Mission Elapsed Time
    float AltitudeM,
    float VelocityMps,
    float ChamberPressureBar,
    float PropellantPct);

// ----------------------------------------------------------------------------
// 2. CCSDS Space Packet codec (CCSDS 133.0-B-2)
//    Primary header: 6 bytes. Secondary header: 8-byte MET. User data: 4 x float32.
// ----------------------------------------------------------------------------
public static class CcsdsCodec
{
    public const int PrimaryHeaderLen = 6;
    public const int SecondaryHeaderLen = 8;
    public const int UserDataLen = 16;
    public const int PacketLen = PrimaryHeaderLen + SecondaryHeaderLen + UserDataLen;

    public static byte[] Encode(in TelemetryFrame f)
    {
        var buf = new byte[PacketLen];
        var span = buf.AsSpan();

        // Version(3)=0 | Type(1)=0 (telemetry) | SecHdrFlag(1)=1 | APID(11)
        ushort word0 = (ushort)((1 << 11) | (f.Apid & 0x7FF));
        // SeqFlags(2)=3 (unsegmented) | SeqCount(14)
        ushort word1 = (ushort)((3 << 14) | (f.SequenceCount & 0x3FFF));
        // Packet data length = (bytes in data field) - 1
        ushort word2 = (ushort)(SecondaryHeaderLen + UserDataLen - 1);

        BinaryPrimitives.WriteUInt16BigEndian(span[0..2], word0);
        BinaryPrimitives.WriteUInt16BigEndian(span[2..4], word1);
        BinaryPrimitives.WriteUInt16BigEndian(span[4..6], word2);
        BinaryPrimitives.WriteInt64BigEndian(span[6..14], f.MetMillis);
        BinaryPrimitives.WriteSingleBigEndian(span[14..18], f.AltitudeM);
        BinaryPrimitives.WriteSingleBigEndian(span[18..22], f.VelocityMps);
        BinaryPrimitives.WriteSingleBigEndian(span[22..26], f.ChamberPressureBar);
        BinaryPrimitives.WriteSingleBigEndian(span[26..30], f.PropellantPct);
        return buf;
    }

    public static bool TryDecode(ReadOnlySpan<byte> span, out TelemetryFrame frame)
    {
        frame = default;
        if (span.Length < PrimaryHeaderLen) return false;

        ushort word0 = BinaryPrimitives.ReadUInt16BigEndian(span[0..2]);
        ushort word1 = BinaryPrimitives.ReadUInt16BigEndian(span[2..4]);
        ushort word2 = BinaryPrimitives.ReadUInt16BigEndian(span[4..6]);

        int version = word0 >> 13;
        bool hasSecHdr = ((word0 >> 11) & 1) == 1;
        ushort apid = (ushort)(word0 & 0x7FF);
        ushort seq = (ushort)(word1 & 0x3FFF);
        int dataLen = word2 + 1;

        if (version != 0 || !hasSecHdr) return false;
        if (span.Length < PrimaryHeaderLen + dataLen) return false;   // truncated packet
        if (dataLen != SecondaryHeaderLen + UserDataLen) return false; // unexpected layout

        frame = new TelemetryFrame(
            apid, seq,
            BinaryPrimitives.ReadInt64BigEndian(span[6..14]),
            BinaryPrimitives.ReadSingleBigEndian(span[14..18]),
            BinaryPrimitives.ReadSingleBigEndian(span[18..22]),
            BinaryPrimitives.ReadSingleBigEndian(span[22..26]),
            BinaryPrimitives.ReadSingleBigEndian(span[26..30]));
        return true;
    }
}

// ----------------------------------------------------------------------------
// 3. Ingest: UDP socket -> bounded channel (backpressure: drop oldest if display can't keep up)
// ----------------------------------------------------------------------------
public sealed class UdpTelemetryReceiver
{
    private readonly UdpClient _udp;
    private readonly ChannelWriter<byte[]> _out;

    public UdpTelemetryReceiver(int port, ChannelWriter<byte[]> output)
    {
        _udp = new UdpClient(port);
        _out = output;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var result = await _udp.ReceiveAsync(ct);
                await _out.WriteAsync(result.Buffer, ct);
            }
        }
        catch (OperationCanceledException) { }
        finally { _out.TryComplete(); _udp.Dispose(); }
    }
}

// ----------------------------------------------------------------------------
// 4. Processing: decode, sequence-gap detection, limit checking, fan-out to display
// ----------------------------------------------------------------------------
public sealed record Alarm(long MetMillis, string Severity, string Message);

public sealed class TelemetryProcessor
{
    private readonly ChannelReader<byte[]> _in;
    private readonly ChannelWriter<TelemetryFrame> _frames;
    private readonly ChannelWriter<Alarm> _alarms;
    private int _lastSeq = -1;
    private int _dropped, _corrupt;
    private readonly HashSet<string> _active = new();   // alarms currently latched on

    public TelemetryProcessor(ChannelReader<byte[]> input,
                              ChannelWriter<TelemetryFrame> frames,
                              ChannelWriter<Alarm> alarms)
    { _in = input; _frames = frames; _alarms = alarms; }

    public (int Dropped, int Corrupt) Stats => (_dropped, _corrupt);

    // Latching alarm: announce once when the condition trips, once when it clears.
    private async Task UpdateAlarmAsync(string key, bool tripped, long met, string severity, string message, CancellationToken ct)
    {
        if (tripped && _active.Add(key))
            await _alarms.WriteAsync(new Alarm(met, severity, message), ct);
        else if (!tripped && _active.Remove(key))
            await _alarms.WriteAsync(new Alarm(met, "INFO", $"{key} cleared"), ct);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        await foreach (var raw in _in.ReadAllAsync(ct))
        {
            if (!CcsdsCodec.TryDecode(raw, out var f))
            {
                _corrupt++;
                await _alarms.WriteAsync(new Alarm(-1, "WARN", $"Undecodable packet ({raw.Length} bytes)"), ct);
                continue;
            }

            // Sequence continuity (14-bit counter wraps at 16384)
            if (_lastSeq >= 0)
            {
                int expected = (_lastSeq + 1) & 0x3FFF;
                if (f.SequenceCount != expected)
                {
                    int gap = (f.SequenceCount - expected) & 0x3FFF;
                    _dropped += gap;
                    await _alarms.WriteAsync(new Alarm(f.MetMillis, "WARN", $"Sequence gap: {gap} packet(s) lost"), ct);
                }
            }
            _lastSeq = f.SequenceCount;

            // Limit checks (red lines a launch conductor would be watching)
            await UpdateAlarmAsync("PRESSURE_LOW", f.ChamberPressureBar < 60f && f.MetMillis > 2000,
                f.MetMillis, "RED", $"Chamber pressure LOW: {f.ChamberPressureBar:F1} bar", ct);
            await UpdateAlarmAsync("PROPELLANT_LOW", f.PropellantPct < 10f,
                f.MetMillis, "AMBER", $"Propellant {f.PropellantPct:F1}%", ct);

            await _frames.WriteAsync(f, ct);
        }
        _frames.TryComplete();
        _alarms.TryComplete();
    }
}

// ----------------------------------------------------------------------------
// 5. Simulated launch vehicle: 20 Hz, injects an engine anomaly at T+30 s
//    and a 5-packet dropout at T+15 s. Replace with a real adapter later.
// ----------------------------------------------------------------------------
public sealed class VehicleSimulator
{
    private readonly UdpClient _udp = new();
    private readonly IPEndPoint _dest;
    public VehicleSimulator(int port) => _dest = new IPEndPoint(IPAddress.Loopback, port);

    public async Task RunAsync(CancellationToken ct)
    {
        const int hz = 20;
        ushort seq = 0;
        float alt = 0, vel = 0, pressure = 100, prop = 100;
        var t0 = DateTime.UtcNow;

        while (!ct.IsCancellationRequested)
        {
            long met = (long)(DateTime.UtcNow - t0).TotalMilliseconds;
            float dt = 1f / hz;

            if (met > 30_000) pressure = Math.Max(0, pressure - 4f * dt * 10); // engine anomaly
            float accel = pressure / 100f * 25f;                                 // ~2.5 g nominal
            vel += (accel - 9.81f) * dt;
            alt += vel * dt;

            // Ground: once off the pad, returning to 0 m means impact. Clamp and end the run.
            bool impact = met > 1000 && alt <= 0;
            if (impact) { alt = 0; vel = 0; }
            prop = Math.Max(0, prop - 0.8f * dt);

            var frame = new TelemetryFrame(Apid: 0x0A1, seq, met, alt, vel, pressure, prop);
            seq = (ushort)((seq + 1) & 0x3FFF);

            bool dropout = met is > 15_000 and < 15_250;                         // simulated link loss
            if (!dropout)
                await _udp.SendAsync(CcsdsCodec.Encode(frame), _dest, ct);

            if (impact)
            {
                Console.WriteLine($"  [SIM  ] Vehicle impact at T+{met / 1000.0:F1}s - simulation ended");
                break;
            }

            await Task.Delay(1000 / hz, ct);
        }
    }
}

// ----------------------------------------------------------------------------
// 6. Operator console wiring
// ----------------------------------------------------------------------------
public static class Program
{
    public static async Task Main()
    {
        const int port = 5005;
        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

        var raw = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(1024) { FullMode = BoundedChannelFullMode.DropOldest });
        var frames = Channel.CreateBounded<TelemetryFrame>(new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.DropOldest });
        var alarms = Channel.CreateUnbounded<Alarm>();

        var receiver = new UdpTelemetryReceiver(port, raw.Writer);
        var processor = new TelemetryProcessor(raw.Reader, frames.Writer, alarms.Writer);
        var vehicle = new VehicleSimulator(port);

        var tasks = new[]
        {
            receiver.RunAsync(cts.Token),
            processor.RunAsync(cts.Token),
            RunVehicleThenShutdownAsync(vehicle, cts),
            DisplayAsync(frames.Reader, alarms.Reader, processor, cts.Token),
        };

        Console.WriteLine("Ground station up. Ctrl+C to abort.\n");
        try { await Task.WhenAll(tasks); } catch (OperationCanceledException) { }
    }

    // When the simulated vehicle finishes (impact), let the pipeline drain, then shut everything down.
    private static async Task RunVehicleThenShutdownAsync(VehicleSimulator vehicle, CancellationTokenSource cts)
    {
        await vehicle.RunAsync(cts.Token);
        await Task.Delay(1000);
        cts.Cancel();
    }

    private static async Task DisplayAsync(ChannelReader<TelemetryFrame> frames,
                                           ChannelReader<Alarm> alarms,
                                           TelemetryProcessor proc,
                                           CancellationToken ct)
    {
        var alarmTask = Task.Run(async () =>
        {
            await foreach (var a in alarms.ReadAllAsync(ct))
                Console.WriteLine($"  [{a.Severity,-5}] T+{a.MetMillis / 1000.0,6:F1}s  {a.Message}");
        }, ct);

        long nextPrint = 0;
        await foreach (var f in frames.ReadAllAsync(ct))
        {
            if (f.MetMillis < nextPrint) continue;       // throttle display to 2 Hz
            nextPrint = f.MetMillis + 500;
            var (dropped, corrupt) = proc.Stats;
            Console.WriteLine(
                $"T+{f.MetMillis / 1000.0,6:F1}s  ALT {f.AltitudeM,9:F0} m  VEL {f.VelocityMps,7:F1} m/s  " +
                $"Pc {f.ChamberPressureBar,5:F1} bar  PROP {f.PropellantPct,5:F1}%  seq {f.SequenceCount,5}  " +
                $"lost {dropped} bad {corrupt}");
        }
        await alarmTask;
    }
}