//! Converting a video before it is sent.
//!
//! A share is only as useful as what the other side can play, and a phone
//! recording, a screen capture or a rip can be anything at all. So a video that
//! is not already AV1 is converted on the sender's machine, before encryption,
//! into AV1 in an MP4 that a browser plays — the one format every receiver in
//! this project can show without a plugin.
//!
//! The encoder is the `ffmpeg` sidecar (`docs/sidecars.md`), never a library we
//! link: LGPL stays outside the binary. This module decides *what* to run, and
//! runs it:
//!
//! * [`probe`] asks ffmpeg what a file holds (codec, size, duration, audio), so
//!   a file that is already AV1 is sent untouched and nothing is re-encoded for
//!   no reason.
//! * [`plan`] turns a [`Profile`] and what this particular ffmpeg can encode
//!   with into a command line, falling back to SVT-AV1 when a hardware encoder
//!   is missing.
//! * [`convert`] runs it and reports progress from ffmpeg's own `-progress`
//!   stream, so a two-hour film shows a moving bar rather than a spinner.
//!
//! Conversion is optional: a client without ffmpeg still shares the file as it
//! is, and the caller decides whether to offer the choice at all
//! ([`available`]).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};

/// What a conversion is for: how much time to spend for how little file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The GPU encoder if the build has one: minutes saved, a few megabytes
    /// more. What a quick share of a phone clip wants.
    Fast,
    /// SVT-AV1 at a moderate preset: the default, and what the design calls
    /// Balanced.
    Balanced,
    /// SVT-AV1, slower preset, better quality: for a film that will be watched
    /// more than once.
    Quality,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::Fast, Profile::Balanced, Profile::Quality];

    /// The stable name used in settings, arguments and the UI's bridge.
    pub fn key(self) -> &'static str {
        match self {
            Profile::Fast => "fast",
            Profile::Balanced => "balanced",
            Profile::Quality => "quality",
        }
    }

    /// What a person calls it.
    pub fn label(self) -> &'static str {
        match self {
            Profile::Fast => "small & fast",
            Profile::Balanced => "balanced",
            Profile::Quality => "quality",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.key() == s.trim().to_ascii_lowercase())
    }
}

/// Which AV1 encoders this ffmpeg was built with or can reach. A hardware
/// encoder named here can still refuse at run time (no such GPU); the fallback
/// is then SVT-AV1 at the Balanced settings, never a failure of the share.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Encoders {
    pub svt_av1: bool,
    pub nvenc: bool,
    pub qsv: bool,
    pub amf: bool,
}

impl Encoders {
    /// Whether a conversion can produce AV1 at all.
    pub fn any(&self) -> bool {
        self.svt_av1 || self.nvenc || self.qsv || self.amf
    }
}

/// What ffmpeg says this build can encode with: `ffmpeg -encoders`.
pub fn encoders(ffmpeg: &Path) -> Result<Encoders> {
    let out = std::process::Command::new(ffmpeg)
        .args(["-hide_banner", "-encoders"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .with_context(|| format!("running {}", ffmpeg.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let has = |name: &str| text.lines().any(|l| l.split_whitespace().nth(1) == Some(name));
    Ok(Encoders {
        svt_av1: has("libsvtav1"),
        nvenc: has("av1_nvenc"),
        qsv: has("av1_qsv"),
        amf: has("av1_amf"),
    })
}

/// Whether a client can convert video at all: the sidecar is there and it can
/// encode AV1. A caller that gets `None` offers "send as it is" only.
pub fn available() -> Option<PathBuf> {
    let ffmpeg = crate::sidecar::find(crate::sidecar::Tool::Ffmpeg)?;
    let ok = encoders(&ffmpeg).map(|e| e.svt_av1).unwrap_or(false);
    ok.then_some(ffmpeg)
}

/// The parts of a file that decide what to do with it.
#[derive(Clone, Debug)]
pub struct Media {
    /// The video codec's name as ffmpeg gives it: `h264`, `hevc`, `av1`, …
    pub video_codec: String,
    pub width: u32,
    pub height: u32,
    /// The pixel format, if ffmpeg named one (`yuv420p`, `yuv420p10le`, …). A
    /// browser plays 8- and 10-bit 4:2:0; anything else has to be converted.
    pub pix_fmt: Option<String>,
    pub audio_codec: Option<String>,
    /// Seconds. `0.0` when ffmpeg does not say (a pipe, a broken header).
    pub duration: f64,
}

impl Media {
    /// Whether this file is already what a browser can play: AV1 in 4:2:0 at 8
    /// or 10 bits. Then it is sent as it is — a re-encode would only lose.
    pub fn is_playable_av1(&self) -> bool {
        self.video_codec == "av1"
            && matches!(self.pix_fmt.as_deref(), None | Some("yuv420p") | Some("yuv420p10le"))
    }
}

/// `hh:mm:ss.ss` as ffmpeg prints it.
fn parse_duration(s: &str) -> f64 {
    let mut parts = s.split(':');
    let (Some(h), Some(m), Some(sec)) = (parts.next(), parts.next(), parts.next()) else {
        return 0.0;
    };
    let sec: f64 = sec.parse().unwrap_or(0.0);
    h.parse::<f64>().unwrap_or(0.0) * 3600.0 + m.parse::<f64>().unwrap_or(0.0) * 60.0 + sec
}

/// Read what a file holds from ffmpeg's own description of it (`ffmpeg -i`,
/// which exits non-zero on purpose: there is no output file).
pub fn probe(ffmpeg: &Path, input: &Path) -> Result<Media> {
    let out = std::process::Command::new(ffmpeg)
        .args(["-hide_banner", "-i"])
        .arg(input)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {}", ffmpeg.display()))?;
    let text = String::from_utf8_lossy(&out.stderr);
    let mut media = Media {
        video_codec: String::new(),
        width: 0,
        height: 0,
        pix_fmt: None,
        audio_codec: None,
        duration: 0.0,
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Duration: ") {
            if let Some(up_to) = rest.split(',').next() {
                media.duration = parse_duration(up_to.trim());
            }
        }
        // `Stream #0:0[0x1](und): Video: h264 (High) (avc1 / 0x31637661),
        //  yuv420p(progressive), 1920x1080 [SAR 1:1 DAR 16:9], 25 fps, …`
        let Some((kind, rest)) = line
            .split_once(": Video: ")
            .map(|(head, rest)| ("video", (head, rest)))
            .or_else(|| line.split_once(": Audio: ").map(|(head, rest)| ("audio", (head, rest))))
        else {
            continue;
        };
        let (head, rest) = rest;
        // only real streams count: a cover picture is "Video: mjpeg" too, but
        // it comes after "attached pic"
        if head.contains("attached pic") {
            continue;
        }
        let codec = rest.split([',', ' ']).next().unwrap_or("").to_string();
        if kind == "audio" {
            media.audio_codec = Some(codec);
            continue;
        }
        media.video_codec = codec;
        for field in rest.split(',').map(str::trim) {
            if let Some((w, h)) = field.split_once('x') {
                let (w, h) = (w.trim(), h.split(|c: char| !c.is_ascii_digit()).next().unwrap_or(""));
                if let (Ok(w), Ok(h)) = (w.parse::<u32>(), h.parse::<u32>()) {
                    if media.width == 0 {
                        media.width = w;
                        media.height = h;
                    }
                }
            } else if field.starts_with("yuv")
                || field.starts_with("gray")
                || field.starts_with("nv12")
                || field.starts_with("p010")
                || field.starts_with("gbr")
            {
                media.pix_fmt = Some(field.split('(').next().unwrap_or(field).to_string());
            }
        }
    }
    if media.video_codec.is_empty() {
        bail!("{} has no video stream ffmpeg can see", input.display());
    }
    Ok(media)
}

/// What to do with one file.
#[derive(Clone, Debug)]
pub enum Plan {
    /// Already AV1: send the file itself.
    AsIs,
    /// Convert into `out` with `args` (ffmpeg's arguments, program excluded).
    Convert { out: PathBuf, args: Vec<String> },
}

/// The video encoder arguments for a profile, given what this ffmpeg has.
pub fn encoder_args(profile: Profile, encoders: &Encoders) -> Vec<String> {
    let svt = |preset: &str, crf: &str, grain: &str| {
        vec![
            "-c:v".into(),
            "libsvtav1".into(),
            "-preset".into(),
            preset.into(),
            "-crf".into(),
            crf.into(),
            "-svtav1-params".into(),
            format!("tune=0:film-grain={grain}"),
        ]
    };
    match profile {
        // A hardware encoder if there is one; otherwise the Balanced settings,
        // because a slow software encode under a name that promises speed is a
        // worse answer than an honest one.
        Profile::Fast => {
            if encoders.nvenc {
                ["-c:v", "av1_nvenc", "-preset", "p5", "-tune", "hq", "-rc", "vbr", "-cq", "34", "-b:v", "0"]
                    .map(String::from)
                    .to_vec()
            } else if encoders.qsv {
                ["-c:v", "av1_qsv", "-preset", "fast", "-global_quality", "34"].map(String::from).to_vec()
            } else if encoders.amf {
                ["-c:v", "av1_amf", "-quality", "speed", "-qp_i", "34", "-qp_p", "34"].map(String::from).to_vec()
            } else {
                svt("8", "32", "8")
            }
        }
        Profile::Balanced => svt("8", "32", "8"),
        Profile::Quality => svt("5", "30", "12"),
    }
}

/// Decide what to do with `input`, converting into `out` if it has to be
/// converted. `out` is only used for a conversion.
pub fn plan(input: &Path, media: &Media, profile: Profile, encoders: &Encoders, out: PathBuf) -> Plan {
    if media.is_playable_av1() {
        return Plan::AsIs;
    }
    let mut args: Vec<String> = vec!["-hide_banner".into(), "-nostdin".into(), "-y".into(), "-i".into()];
    args.push(input.display().to_string());
    // the picture, and only the picture (a subtitle track or a cover picture
    // would make MP4 refuse what it cannot carry)
    args.extend(["-map", "0:v:0", "-map", "0:a?"].map(String::from));
    args.extend(encoder_args(profile, encoders));
    args.extend(["-pix_fmt", "yuv420p10le"].map(String::from));
    // lossless audio passthrough where MP4 can carry it, otherwise AAC: a
    // conversion should not spend its time on the sound
    match media.audio_codec.as_deref() {
        Some("aac") | Some("mp3") | Some("alac") | Some("opus") => args.extend(["-c:a", "copy"].map(String::from)),
        Some(_) => args.extend(["-c:a", "aac", "-b:a", "160k"].map(String::from)),
        None => args.extend(["-an"].map(String::from)),
    }
    // a faststart MP4 puts its index at the front, so a page can start playing
    // from the first block instead of waiting for the last
    args.extend(["-movflags", "+faststart", "-f", "mp4"].map(String::from));
    args.push("-progress".into());
    args.push("pipe:1".into());
    args.push("-nostats".into());
    args.push(out.display().to_string());
    Plan::Convert { out, args }
}

/// Run a conversion, calling `progress` with the fraction done (0..1) as
/// ffmpeg reports it. `duration` is the source's length, from [`probe`].
pub async fn convert<F>(ffmpeg: &Path, args: &[String], duration: f64, mut progress: F) -> Result<()>
where
    F: FnMut(f64),
{
    let mut child = tokio::process::Command::new(ffmpeg)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("running {}", ffmpeg.display()))?;
    let stdout = child.stdout.take().expect("piped");
    let mut lines = BufReader::new(stdout).lines();
    // the last few lines of stderr are the only useful part of a failure
    let stderr = child.stderr.take().expect("piped");
    let errors = tokio::spawn(async move {
        let mut tail: Vec<String> = Vec::new();
        let mut lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tail.push(line);
            if tail.len() > 12 {
                tail.remove(0);
            }
        }
        tail.join("\n")
    });
    while let Some(line) = lines.next_line().await? {
        // `out_time_us=1234567` and `progress=continue|end`
        if let Some(value) = line.strip_prefix("out_time_us=") {
            if duration > 0.0 {
                if let Ok(us) = value.trim().parse::<f64>() {
                    progress((us / 1_000_000.0 / duration).clamp(0.0, 1.0));
                }
            }
        }
    }
    let status = child.wait().await?;
    let tail = errors.await.unwrap_or_default();
    if !status.success() {
        bail!("ffmpeg failed ({}): {}", status, tail.trim());
    }
    progress(1.0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ffmpeg() -> Option<PathBuf> {
        let p = crate::sidecar::find(crate::sidecar::Tool::Ffmpeg)?;
        let enc = encoders(&p).ok()?;
        enc.svt_av1.then_some(p)
    }

    /// A one-second test clip, encoded with whatever this ffmpeg has for h264.
    fn sample(dir: &Path, name: &str) -> PathBuf {
        for codec in ["libx264", "mpeg4"] {
            let path = dir.join(name);
            let ok = std::process::Command::new("ffmpeg")
                .args(["-hide_banner", "-y", "-f", "lavfi", "-i", "testsrc=size=160x120:rate=10:duration=1"])
                .args(["-c:v", codec, "-pix_fmt", "yuv420p"])
                .arg(&path)
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                return path;
            }
        }
        panic!("no h264 or mpeg4 encoder to make a sample with");
    }

    #[test]
    fn durations_read_as_ffmpeg_prints_them() {
        assert!((parse_duration("00:01:30.50") - 90.5).abs() < 0.001);
        assert!((parse_duration("01:00:00.00") - 3600.0).abs() < 0.001);
        assert_eq!(parse_duration("nonsense"), 0.0);
    }

    #[test]
    fn a_file_that_is_already_av1_is_not_converted() {
        let media = Media {
            video_codec: "av1".into(),
            width: 1920,
            height: 1080,
            pix_fmt: Some("yuv420p10le".into()),
            audio_codec: Some("opus".into()),
            duration: 10.0,
        };
        let encoders = Encoders { svt_av1: true, ..Default::default() };
        let plan = plan(Path::new("in.mkv"), &media, Profile::Balanced, &encoders, PathBuf::from("out.mp4"));
        assert!(matches!(plan, Plan::AsIs));
    }

    #[test]
    fn a_promised_profile_falls_back_to_software_rather_than_a_name() {
        // no hardware encoder in this build
        let encoders = Encoders { svt_av1: true, ..Default::default() };
        let fast = encoder_args(Profile::Fast, &encoders);
        assert_eq!(fast[1], "libsvtav1", "fast without a GPU is SVT-AV1, not a lie");
        let with_nvenc = Encoders { svt_av1: true, nvenc: true, ..Default::default() };
        assert_eq!(encoder_args(Profile::Fast, &with_nvenc)[1], "av1_nvenc");
    }

    #[test]
    fn the_command_carries_the_profiles_numbers() {
        let encoders = Encoders { svt_av1: true, ..Default::default() };
        let media = Media {
            video_codec: "h264".into(),
            width: 640,
            height: 480,
            pix_fmt: Some("yuv420p".into()),
            audio_codec: Some("aac".into()),
            duration: 2.0,
        };
        let Plan::Convert { args, .. } = plan(Path::new("in.mkv"), &media, Profile::Quality, &encoders, PathBuf::from("out.mp4")) else {
            panic!("h264 has to be converted");
        };
        let joined = args.join(" ");
        assert!(joined.contains("-preset 5"), "{joined}");
        assert!(joined.contains("-crf 30"), "{joined}");
        assert!(joined.contains("-pix_fmt yuv420p10le"), "{joined}");
        assert!(joined.contains("-c:a copy"), "{joined}");
        assert!(joined.contains("-movflags +faststart"), "{joined}");
    }

    /// The whole path, with the real encoder: a short clip goes in as h264 and
    /// comes out as AV1 a browser plays.
    #[tokio::test]
    async fn a_clip_is_converted_to_av1_and_can_be_probed_back() {
        let Some(ffmpeg) = ffmpeg() else {
            eprintln!("no ffmpeg with libsvtav1: skipping");
            return;
        };
        let dir = std::env::temp_dir().join(format!("bitmule-video-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = sample(&dir, "sample.mp4");
        let enc = encoders(&ffmpeg).unwrap();
        let media = probe(&ffmpeg, &input).unwrap();
        assert_eq!(media.video_codec, "h264");
        assert_eq!((media.width, media.height), (160, 120));

        let out = dir.join("sample.av1.mp4");
        let Plan::Convert { args, .. } = plan(&input, &media, Profile::Balanced, &enc, out.clone()) else {
            panic!("h264 has to be converted");
        };
        let mut seen = Vec::new();
        convert(&ffmpeg, &args, media.duration, |f| seen.push(f)).await.unwrap();
        assert_eq!(seen.last(), Some(&1.0));

        let after = probe(&ffmpeg, &out).unwrap();
        assert_eq!(after.video_codec, "av1", "the output is AV1");
        assert!(after.is_playable_av1(), "{after:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
