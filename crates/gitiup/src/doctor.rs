//! `gitiup doctor --sandbox`: what is active here, what is missing, and what to do.
//!
//! The command exists because the alternative is a volunteer discovering the facts by
//! watching `gitiup run --execute` fail. It reports the same probes the runner will
//! use — same code, same order, same refusals — so it cannot describe a machine that
//! the next command then contradicts.
//!
//! The exit code is the verdict, not the formatting: a machine that may not serve a
//! stranger's job exits 6, the same refusal code the rest of the taxonomy uses, so a
//! supervisor can branch on `gitiup doctor --sandbox` instead of reading prose. A
//! machine that may serve, with warnings, exits 0 — warnings are for the human.

use gitiup_sandbox::doctor;

use crate::CliError;
use crate::remotes;

/// Usage for what `doctor` can inspect.
pub const USAGE: &str = "\
gitiup doctor — report what this machine can and cannot confine, and which host
serves which remote.

USAGE:
    gitiup doctor --sandbox [--json]
    gitiup doctor --remotes [--json]

OPTIONS:
    --sandbox     survey the isolation backends: kernel support, each backend's probe,
                  and whether this host may serve a stranger's job at all
    --remotes     for every `[[remote]]` in gitiup.toml, which host serves it and what
                  that host warns about; a forge remote in a build without the forge
                  adapter is named and refused here
    --json        the same report as JSON, for a dashboard or a support ticket

Exit codes: 0 this machine may serve jobs and every remote has a host (warnings
possible — read them) · 6 it may not, or a remote has no host this build can serve ·
2 usage.
";

/// `gitiup doctor …`
pub fn run(args: &[String]) -> Result<(), CliError> {
    let mut sandbox = false;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            // A different subject, with its own report and its own exit conditions:
            // hand the whole argument list over rather than re-parse it here.
            "--remotes" | "--remote" => return remotes::run(args),
            "--sandbox" | "--sandboxes" => sandbox = true,
            "--json" => json = true,
            "--help" | "-h" => {
                print!("{USAGE}");
                return Ok(());
            }
            other => {
                return Err(CliError::usage(format!("unknown doctor flag '{other}'")));
            }
        }
        index += 1;
    }
    if !sandbox {
        // Not a usage error with a nonzero exit: `gitiup doctor` is a reasonable thing
        // to type, and the answer is the list of what can be looked at.
        print!("{USAGE}");
        return Ok(());
    }

    let report = doctor::survey();
    if json {
        println!("{}", report.json());
    } else {
        print!("{}", report.text());
    }
    if report.may_serve_jobs {
        Ok(())
    } else {
        Err(CliError::refused(
            report.verdict.clone(),
            "nothing will be executed from here until a backend probes clean; `gitiup run` \
             will still plan and attest as `simulated`, which is the safe default",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_doctor_flag_is_a_usage_error() {
        let err = run(&["--secrets".into()]).unwrap_err();
        assert_eq!(err.code, 2);
    }

    #[test]
    fn asking_for_nothing_prints_the_usage_without_failing() {
        assert!(run(&[]).is_ok());
    }

    /// The command's whole contract: the exit code is the verdict, so the library's
    /// verdict and this exit code may never disagree.
    #[test]
    fn the_exit_code_is_the_verdict() {
        let report = doctor::survey();
        let outcome = run(&["--sandbox".into()]);
        match (report.may_serve_jobs, outcome) {
            (true, Ok(())) | (false, Err(_)) => {}
            (true, Err(err)) => panic!(
                "the report says jobs may be served, but the command exited {}: {}",
                err.code, err.message
            ),
            (false, Ok(())) => {
                panic!("the report says this machine may not serve jobs, and the command exited 0")
            }
        }
    }

    #[test]
    fn the_json_is_the_same_report() {
        // `--json` must not be a second, thinner report: the point of the flag is that
        // a machine can read the same facts a human reads.
        let text = doctor::survey();
        let json = serde_json::from_str::<serde_json::Value>(&text.json())
            .expect("the JSON parses, or it is not a report a dashboard can read");
        assert_eq!(json["may_serve_jobs"], text.may_serve_jobs);
        assert_eq!(json["verdict"], text.verdict);
        assert_eq!(
            json["backends"].as_array().map(Vec::len),
            Some(text.backends.len())
        );
    }
}
