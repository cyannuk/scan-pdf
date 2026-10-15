//! Node.js wrapper: scanning runs on the libuv thread pool and returns a Promise.

use std::panic::{catch_unwind, AssertUnwindSafe};

use napi::bindgen_prelude::*;
use napi_derive::napi;

use pdf_scan_core as core;

#[napi(object)]
pub struct Options {
    pub max_stream_bytes: Option<f64>,
    pub max_total_bytes: Option<f64>,
    pub max_objects: Option<f64>,
}

#[napi(object)]
pub struct Finding {
    pub name: String,
    pub severity: String,
    pub count: u32,
}

#[napi(object)]
pub struct ScanResult {
    pub suspicious: bool,
    pub encrypted: bool,
    pub findings: Vec<Finding>,
    pub error: Option<String>,
}

pub struct ScanTask {
    /// Reference to the caller's JS buffer: the scanner only reads it, so no copy is made.
    data: Uint8Array,
    opts: core::Options,
}

impl Task for ScanTask {
    type Output = core::ScanResult;
    type JsValue = ScanResult;

    fn compute(&mut self) -> Result<Self::Output> {
        let (data, opts) = (&self.data, &self.opts);
        // a panic in the scanner must not crash the process: turn it into a result with an error
        Ok(catch_unwind(AssertUnwindSafe(|| core::scan(data, opts))).unwrap_or_else(|_| core::ScanResult {
            suspicious: true,
            encrypted: false,
            findings: vec![],
            error: Some("Internal scanner error".into()),
        }))
    }

    fn resolve(&mut self, _env: Env, r: Self::Output) -> Result<Self::JsValue> {
        Ok(ScanResult {
            suspicious: r.suspicious,
            encrypted: r.encrypted,
            findings: r
                .findings
                .into_iter()
                .map(|f| Finding { name: f.name, severity: f.severity.as_str().into(), count: f.count })
                .collect(),
            error: r.error,
        })
    }
}

fn limit(v: Option<f64>, name: &str, def: usize) -> Result<usize> {
    match v {
        None => Ok(def),
        Some(v) if v.is_finite() && v >= 0.0 && v.fract() == 0.0 => Ok(v.min(usize::MAX as f64) as usize),
        Some(v) => Err(Error::new(Status::InvalidArg, format!("{name} must be a non-negative integer, got {v}"))),
    }
}

/// The buffer is read in place on a worker thread (no copy); the task holds a reference to it,
/// so it stays alive until the scan completes.
#[napi(js_name = "scanPdf", ts_return_type = "Promise<ScanResult>")]
pub fn scan_pdf(bytes: Uint8Array, opts: Option<Options>) -> Result<AsyncTask<ScanTask>> {
    let def = core::Options::default();
    let opts = match opts {
        None => def,
        Some(o) => core::Options {
            max_stream_bytes: limit(o.max_stream_bytes, "maxStreamBytes", def.max_stream_bytes)?,
            max_total_bytes: limit(o.max_total_bytes, "maxTotalBytes", def.max_total_bytes)?,
            max_objects: limit(o.max_objects, "maxObjects", def.max_objects)?,
        },
    };
    Ok(AsyncTask::new(ScanTask { data: bytes, opts }))
}
