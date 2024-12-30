use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use ipnetwork::IpNetwork;
use clap::{Command, Arg, value_parser};
use colored::*; // 引入 colored 库
use tokio::sync::Semaphore;
use indicatif::{ProgressBar, ProgressStyle}; // 引入 indicatif 库
use dashmap::DashMap; // 引入 DashMap

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    println!("{}", r#"
 _______   ________  ________  ___  ___  ________  _________  ________  ________  ________  ________
|\  ___ \ |\_____  \|\   __  \|\  \|\  \|\   ____\|\___   ___\\   ____\|\   ____\|\   __  \|\   ___  \
\ \   __/| \|___/  /\ \  \|\  \ \  \\\  \ \  \___|\|___ \  \_\ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \
 \ \  \_|/__   /  / /\ \   _  _\ \  \\\  \ \_____  \   \ \  \ \ \_____  \ \  \    \ \   __  \ \  \\ \  \
  \ \  \_|\ \ /  /_/__\ \  \\  \\ \  \\\  \|____|\  \   \ \  \ \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \
   \ \_______\\________\ \__\\ _\\ \_______\____\_\  \   \ \__\  ____\_\  \ \_______\ \__\ \__\ \__\\ \__\
    \|_______|\|_______|\|__|\|__|\|_______|\_________\   \|__| |\_________\|_______|\|__|\|__|\|__| \|__|
                                           \|_________|         \|_________|
"#.green());

    // 使用 clap 解析命令行参数
    let matches = Command::new("Rust 端口扫描器")
        .version("1.0.1")
        .author("Royoo 3230853833@qq.com")
        .about("高性能端口扫描器，支持IP和网络范围扫描")
        .arg(
            Arg::new("ip")
                .long("ip")
                .value_name("IP")
                .help("指定单个目标IP地址进行扫描")
                .value_parser(value_parser!(String))
                .required(false),
        )
        .arg(
            Arg::new("network")
                .long("network")
                .value_name("NETWORK")
                .help("指定目标网络范围，例如 192.168.1.0/24")
                .value_parser(value_parser!(String))
                .required(false),
        )
        .arg(
            Arg::new("start_port")
                .long("start_port")
                .value_name("START_PORT")
                .help("扫描起始端口")
                .value_parser(value_parser!(u16))
                .required(true),
        )
        .arg(
            Arg::new("end_port")
                .long("end_port")
                .value_name("END_PORT")
                .help("扫描结束端口")
                .value_parser(value_parser!(u16))
                .required(true),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .value_name("TIMEOUT")
                .help("连接超时，单位为秒，默认1秒")
                .default_value("1")
                .value_parser(value_parser!(u64)),
        )
        .arg(
            Arg::new("show_closed")
                .long("show-closed")
                .help("是否输出关闭的端口")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("concurrency")
                .long("concurrency")
                .value_name("CONCURRENCY")
                .help("最大并发数量，默认为 100")
                .default_value("100")
                .value_parser(value_parser!(usize)),
        )
        .get_matches();

    // 获取命令行参数
    let target_ip = matches.get_one::<String>("ip");
    let target_network = matches.get_one::<String>("network");
    let start_port: u16 = *matches.get_one::<u16>("start_port").unwrap();
    let end_port: u16 = *matches.get_one::<u16>("end_port").unwrap();
    let timeout: u64 = *matches.get_one::<u64>("timeout").unwrap();
    let show_closed: bool = matches.get_flag("show_closed");
    let concurrency: usize = *matches.get_one::<usize>("concurrency").unwrap();

    let timeout_duration = Duration::from_secs(timeout);
    let semaphore = Arc::new(Semaphore::new(concurrency)); // 动态设置并发数

    // 记录扫描开始的时间
    let start_time = Instant::now();

    // 如果指定了目标IP地址，则进行单个IP扫描
    if let Some(target_ip) = target_ip {
        println!("开始扫描 IP: {}", target_ip);
        let result = scan_ports(target_ip, start_port, end_port, timeout_duration, semaphore.clone(), show_closed).await;

        // 输出扫描结果
        if result.is_empty() {
            println!("{}", "没有发现开放端口".red());
        } else {
            for port in result {
                println!("{}", format!("端口 {} 开放", port).green());
            }
        }
    }

    // 如果指定了目标网络，则进行网络范围扫描
    if let Some(target_network) = target_network {
        println!("开始扫描网络: {}", target_network);
        let result = scan_network(target_network, start_port, end_port, timeout_duration, semaphore.clone(), show_closed).await;

        // 输出扫描结果
        if result.is_empty() {
            println!("{}", "没有发现开放的IP".red());
        } else {
            for ip in result {
                println!("{}", format!("IP地址 {} 有开放端口", ip).green());
            }
        }
    }

    // 打印总扫描时间
    let elapsed = start_time.elapsed();
    println!("{}", format!("扫描完成，总耗时: {:?}", elapsed).yellow());
}

// 扫描一个指定的IP和端口范围
async fn scan_ports(
    ip: &str,
    start_port: u16,
    end_port: u16,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
    show_closed: bool,
) -> Vec<u16> {
    let ip: std::net::IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("无效的IP地址 {}: {}", ip, e);
            return Vec::new();
        }
    };

    let results = Arc::new(DashMap::new()); // 使用 DashMap 替代 Mutex
    let mut handles = Vec::new();

    // 初始化进度条
    let pb = ProgressBar::new((end_port - start_port + 1) as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{wide_bar} {pos}/{len} [{elapsed_precise}]")
        .expect("Failed to create ProgressStyle")
        .progress_chars("##-"));

    for port in start_port..=end_port {
        let semaphore_clone = semaphore.clone();
        let results_clone = results.clone();
        let pb = pb.clone();
        let ip = ip.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore_clone.acquire_owned().await.unwrap(); // 获取许可

            // 扫描单个端口
            let (port, is_open) = scan_single_port(ip, port, timeout, show_closed).await;

            if is_open {
                results_clone.insert(port, true);
            }

            pb.inc(1); // 更新进度条
            drop(permit); // 释放许可
        });
        handles.push(handle);
    }

    // 等待所有任务完成
    for handle in handles {
        if let Err(e) = handle.await {
            eprintln!("任务执行出错: {}", e);
        }
    }

    pb.finish_with_message("扫描完成");

    // 收集结果
    results.iter().map(|entry| *entry.key()).collect()
}

// 扫描单个端口
async fn scan_single_port(ip: std::net::IpAddr, port: u16, timeout: Duration, show_closed: bool) -> (u16, bool) {
    let addr = format!("{}:{}", ip, port);
    let result = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await;

    if result.is_ok() {
        println!("{}", format!("端口 {} 开放", port).green());
        (port, true)
    } else {
        if show_closed {
            println!("{}", format!("端口 {} 未开放", port).red());
        }
        (port, false)
    }
}

// 扫描整个网络范围
async fn scan_network(
    network: &str,
    start_port: u16,
    end_port: u16,
    timeout: Duration,
    semaphore: Arc<Semaphore>,
    show_closed: bool,
) -> Vec<String> {
    let network = match network.parse::<IpNetwork>() {
        Ok(net) => net,
        Err(e) => {
            eprintln!("无效的网络地址 {}: {}", network, e);
            return Vec::new();
        }
    };

    let open_ips = Arc::new(DashMap::new()); // 使用 DashMap 替代 Mutex
    let mut handles = Vec::new();

    // 初始化进度条，判断网络范围大小并确保类型一致
    let pb = ProgressBar::new({
        match network.size() {
            ipnetwork::NetworkSize::V4(size) => size as u64,
            ipnetwork::NetworkSize::V6(size) => {
                if size > u64::MAX as u128 {
                    u64::MAX // 如果大于 u64 范围，使用 u64::MAX
                } else {
                    size as u64
                }
            }
        }
    });
    pb.set_style(ProgressStyle::default_bar()
        .template("{wide_bar} {pos}/{len} [{elapsed_precise}]")
        .expect("Failed to set style")
        .progress_chars("##-"));

    for ip in network.iter() {
        let open_ips = Arc::clone(&open_ips);
        let ip_str = ip.to_string();
        let semaphore = semaphore.clone();
        let pb = pb.clone();

        let handle = tokio::spawn(async move {
            let permit = semaphore.clone().acquire_owned().await.unwrap();

            let open_ports = scan_ports(&ip_str, start_port, end_port, timeout, semaphore.clone(), show_closed).await;

            if !open_ports.is_empty() {
                open_ips.insert(ip_str, true);
            }

            pb.inc(1); // 更新进度条
            drop(permit); // 释放许可
        });

        handles.push(handle);
    }

    // 等待所有任务完成
    for handle in handles {
        if let Err(e) = handle.await {
            eprintln!("任务执行出错: {}", e);
        }
    }

    pb.finish_with_message("网络扫描完成");

    open_ips.iter().map(|entry| entry.key().clone()).collect()
}