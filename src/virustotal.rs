use owo_colors::{OwoColorize, Stream::Stdout};
use std::thread::sleep;
use std::time::Duration;
use virustotal::{FileReportResponse, VtClient};

#[derive(Debug)]
pub struct VirusTotal {
    pub api_key: Option<String>,
    pub bypass_target: Option<String>,
    pub is_enabled: bool,
}

impl VirusTotal {
    pub fn check_one(&self, path: String) -> bool {
        let vt = VtClient::new(self.api_key.as_ref().unwrap().as_str());
        let res = vt.scan_file(path.as_str());
        let id = res.scan_id.unwrap();

        println!(
            "{} Waiting for VirusTotal scan ..",
            "[+]".if_supports_color(Stdout, |text| text.green())
        );

        let mut scan_results: FileReportResponse;
        loop {
            sleep(Duration::from_secs(15));
            scan_results = vt.report_file(id.as_str());
            println!(
                "VirusTotal message log: {} ..",
                scan_results
                    .verbose_msg
                    .if_supports_color(Stdout, |text| text.yellow())
            );
            if scan_results.verbose_msg == "Scan finished, information embedded" {
                break;
            }
        }

        scan_results
            .scans
            .unwrap()
            .get(self.bypass_target.as_ref().unwrap().as_str())
            .unwrap()
            .detected
            .unwrap()
    }
    pub fn check(&self, path: String) {
        let vt = VtClient::new(self.api_key.as_ref().unwrap().as_str());
        let res = vt.scan_file(path.as_str());
        let id = res.scan_id.unwrap();

        println!(
            "{} Waiting for VirusTotal scan ..",
            "[+]".if_supports_color(Stdout, |text| text.green())
        );

        let mut scan_results: FileReportResponse;
        loop {
            sleep(Duration::from_secs(20));
            scan_results = vt.report_file(id.as_str());
            println!(
                "Virus Total message log: {}",
                scan_results
                    .verbose_msg
                    .if_supports_color(Stdout, |text| text.yellow())
            );
            if scan_results.verbose_msg == "Scan finished, information embedded" {
                break;
            }
        }

        match scan_results.positives.unwrap() as f32 / scan_results.total.unwrap() as f32 * 100.0 {
            value if value < 7.0 => println!(
                "\n{} Scan results: {} / {}, detect rate: {}%",
                "[+]".if_supports_color(Stdout, |text| text.green()),
                scan_results
                    .positives
                    .unwrap()
                    .to_string()
                    .if_supports_color(Stdout, |text| text.green()),
                scan_results
                    .total
                    .unwrap()
                    .to_string()
                    .if_supports_color(Stdout, |text| text.green()),
                (scan_results.positives.unwrap() as f32 / scan_results.total.unwrap() as f32
                    * 100.0)
                    .to_string()
                    .if_supports_color(Stdout, |text| text.green())
            ),
            value if value < 15.0 => println!(
                "\n{} Scan results: {} / {}, detect rate: {}%",
                "[+]".if_supports_color(Stdout, |text| text.green()),
                scan_results
                    .positives
                    .unwrap()
                    .to_string()
                    .if_supports_color(Stdout, |text| text.yellow()),
                scan_results
                    .total
                    .unwrap()
                    .to_string()
                    .if_supports_color(Stdout, |text| text.yellow()),
                (scan_results.positives.unwrap() as f32 / scan_results.total.unwrap() as f32
                    * 100.0)
                    .to_string()
                    .if_supports_color(Stdout, |text| text.yellow())
            ),
            _ => {
                println!(
                    "\n{} Scan results: {} / {}, detect rate: {}%",
                    "[+]".if_supports_color(Stdout, |text| text.green()),
                    scan_results
                        .positives
                        .unwrap()
                        .to_string()
                        .if_supports_color(Stdout, |text| text.red()),
                    scan_results
                        .total
                        .unwrap()
                        .to_string()
                        .if_supports_color(Stdout, |text| text.red()),
                    (scan_results.positives.unwrap() as f32 / scan_results.total.unwrap() as f32
                        * 100.0)
                        .to_string()
                        .if_supports_color(Stdout, |text| text.red())
                )
            }
        }

        for scan in scan_results.scans.unwrap() {
            print!("{} ", scan.0);
            match scan.1.detected.as_ref().unwrap() {
                true => {
                    print!(
                        "{}",
                        "detected".if_supports_color(Stdout, |text| text.red())
                    )
                }
                false => {
                    print!(
                        "{}",
                        "not detected".if_supports_color(Stdout, |text| text.green())
                    )
                }
            };
            match scan.1.result {
                Some(message) => println!(
                    ", message: {}",
                    message.if_supports_color(Stdout, |text| text.yellow())
                ),
                None => println!(),
            };
        }
    }
}
