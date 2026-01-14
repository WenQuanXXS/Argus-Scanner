import json
import os
import argparse
from typing import List, Dict

def load_json(filepath):
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return None
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def evaluate(report_path: str, ground_truth_path: str):
    report_data = load_json(report_path)
    gt_data = load_json(ground_truth_path)

    if not report_data or not gt_data:
        return

    report_findings = report_data.get('findings', [])
    ground_truth = gt_data.get('ground_truth', [])

    total_expected = 0
    total_detected = 0
    missed_findings = []
    false_positives = 0

    print("=" * 60)
    print(f"Argus-Scanner Performance Evaluation Report")
    print(f"Report: {os.path.basename(report_path)}")
    print("=" * 60)

    for gt_item in ground_truth:
        file_path = gt_item['file']
        expected_list = gt_item['expected_findings']
        total_expected += len(expected_list)

        # 过滤出当前文件的报告结果
        file_findings = []
        for f in report_findings:
            r_file = f.get('file', '').replace('\\', '/')
            if file_path in r_file:
                file_findings.append(f)
        
        for expected in expected_list:
            found = False
            for detected in file_findings:
                # 优先匹配 ID
                if 'id' in expected and expected['id'] == detected.get('id'):
                    found = True
                    total_detected += 1
                    break
                
                # 模糊匹配标题或描述
                if expected['title'].lower() in detected['title'].lower() or \
                   expected['title'].lower() in detected.get('description', '').lower():
                    found = True
                    total_detected += 1
                    break
            
            if not found:
                missed_findings.append({
                    "file": file_path,
                    "title": expected['title'],
                    "severity": expected['severity']
                })

    # 计算指标
    fnr = (total_expected - total_detected) / total_expected if total_expected > 0 else 0
    recall = total_detected / total_expected if total_expected > 0 else 0
    
    print(f"\n[Summary Statistics]")
    print(f"- Total Expected Vulnerabilities: {total_expected}")
    print(f"- Total Successfully Detected:  {total_detected}")
    print(f"- Recall (召回率):              {recall:.2%}")
    print(f"- False Negative Rate (漏报率): {fnr:.2%}")

    if missed_findings:
        print(f"\n[CRITICAL] Missed Vulnerabilities (漏报列表):")
        for i, missed in enumerate(missed_findings):
            print(f"{i+1}. [{missed['severity']}] {missed['title']} in {missed['file']}")
    else:
        print(f"\n[SUCCESS] No false negatives detected (0% FNR)!")

    print("\n" + "=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Performance Evaluator for Argus-Scanner")
    parser.add_argument("--report", required=True, help="Path to the JSON report file")
    parser.add_argument("--gt", default=r"f:\网络安全课程设计\CodeSentinel\tests\performance\ground_truth.json", help="Path to ground truth JSON")
    
    args = parser.parse_args()
    evaluate(args.report, args.gt)
