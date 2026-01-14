import os
import sys
import yaml
import subprocess
import json
import argparse
from datetime import datetime

# 添加项目根目录到系统路径
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
sys.path.append(PROJECT_ROOT)

def load_config(config_path):
    """加载 YAML 配置文件"""
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def run_scan(target_path, output_dir):
    """
    对目标路径运行 Argus-Scanner 主程序。
    返回生成的报告文件路径，如果失败则返回 None。
    """
    main_script = os.path.join(PROJECT_ROOT, 'main.py')
    cmd = [
        sys.executable, main_script,
        target_path,
        '--format', 'all',
        '--output', output_dir
    ]
    
    print(f"[*] 正在扫描 {target_path} ...")
    try:
        # 捕获输出以查找生成的报告路径
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        
        # 解析标准输出以查找报告路径
        # 查找行: "[+] 报告已保存到: <path>"
        # 注意: 输出包含 ANSI 颜色代码，因此需要小心处理
        report_path = None
        for line in result.stdout.splitlines():
            if "报告已保存到:" in line:
                # 简单去除 ANSI 转义码
                clean_line = line.replace('\x1b', '').replace('[0m', '').replace('[32m', '')
                parts = clean_line.split("报告已保存到:")
                if len(parts) > 1:
                    path = parts[1].strip()
                # 记录路径。如果是 'all' 格式，main.py 可能只返回 .html 路径
                # 但我们需要 .json 来进行自动分析
                if path.endswith('.json'):
                    report_path = path
                elif path.endswith('.html'):
                    # 尝试推导对应的 JSON 路径 (文件名相同)
                    json_path = path.replace('.html', '.json')
                    if os.path.exists(json_path):
                        report_path = json_path
                    else:
                        # 如果没有找到对应的 json，暂时还是记录原始 html 路径
                        # 后续 analyze_results 会处理文件缺失
                        pass
        
        if report_path and os.path.exists(report_path):
            print(f"[+] 扫描完成。分析报告: {report_path}")
            return report_path
        else:
            print("[-] 扫描完成，但无法从输出中检测到有效的分析文件 (.json)。")
            print(f"    标准输出的最后几行:\n" + "\n".join(result.stdout.splitlines()[-5:]))
            return None

    except subprocess.CalledProcessError as e:
        print(f"[-] 扫描失败: {e}")
        print(f"    错误输出: {e.stderr}")
        return None

def analyze_results(benchmark_name, config, report_path):
    """
    分析扫描报告，与预期结果进行比对。
    """
    if not report_path or not os.path.exists(report_path):
        return {'passed': False, 'details': [f"报告文件未找到: {report_path}"]}

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        findings = data.get('findings', [])
        
        passed = True
        details = []
        
        expected_list = config.get('expected_findings', [])
        for expected in expected_list:
            exp_type = expected.get('type')
            min_count = expected.get('min_count', 1)
            
            # 统计发现的匹配类型数量
            count = sum(1 for f in findings if exp_type.lower() in str(f).lower())
            
            if count >= min_count:
                details.append(f"[通过] 发现 {count} 个 '{exp_type}' 类型问题 (预期 >= {min_count})")
            else:
                passed = False
                details.append(f"[失败] 发现 {count} 个 '{exp_type}' 类型问题 (预期 >= {min_count})")
        
        if not expected_list:
             details.append(f"[信息] 未定义具体的预期结果。总共发现了 {len(findings)} 个问题。")

        return {'passed': passed, 'details': details}

    except Exception as e:
        return {'passed': False, 'details': [f"分析错误: {str(e)}"]}

def main():
    parser = argparse.ArgumentParser(description="Argus-Scanner 性能基准测试运行器")
    parser.add_argument('--target', help="指定运行的特定基准测试 (例如: noriben)")
    parser.add_argument('--check-env', action='store_true', help="检查基准测试目录是否存在")
    args = parser.parse_args()

    config_path = os.path.join(os.path.dirname(__file__), 'benchmark_config.yaml')
    if not os.path.exists(config_path):
        print("[-] 配置文件未找到！")
        sys.exit(1)
        
    config = load_config(config_path)
    benchmarks = config.get('benchmarks', {})

    # 环境检查代码
    if args.check_env:
        print("[*] 正在检查基准测试环境...")
        all_exist = True
        for name, data in benchmarks.items():
            path = os.path.join(PROJECT_ROOT, data['path'])
            if os.path.exists(path):
                print(f"[确认] {name}: {path}")
            else:
                print(f"[缺失] {name}: {path}")
                all_exist = False
        sys.exit(0 if all_exist else 1)

    # 过滤目标
    if args.target:
        if args.target not in benchmarks:
            print(f"[-] 目标 '{args.target}' 在配置中未找到。")
            sys.exit(1)
        benchmarks = {args.target: benchmarks[args.target]}

    # 创建报告目录
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(reports_dir, exist_ok=True)

    # 运行基准测试
    results = {}
    for name, data in benchmarks.items():
        print(f"\n=== 运行基准测试: {name.upper()} ===")
        target_path = os.path.join(PROJECT_ROOT, data['path'])
        
        if not os.path.exists(target_path):
            print(f"[-] 基准测试路径不存在: {target_path}")
            results[name] = {'passed': False, 'details': ["路径缺失"]}
            continue

        report_path = run_scan(target_path, reports_dir)
        
        if report_path:
            analysis = analyze_results(name, data, report_path)
            results[name] = analysis
            for line in analysis['details']:
                print(line)
        else:
             results[name] = {'passed': False, 'details': ["扫描失败或未生成报告"]}

    # 汇总
    print("\n=== 基准测试汇总 ===")
    overall_pass = True
    for name, res in results.items():
        status = "通过" if res['passed'] else "失败"
        print(f"{name}: {status}")
        if not res['passed']:
            overall_pass = False
    
    sys.exit(0 if overall_pass else 1)

if __name__ == "__main__":
    main()
