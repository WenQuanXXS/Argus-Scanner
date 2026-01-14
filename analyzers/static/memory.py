import re
import ast
from typing import List, Dict, Any, Tuple
from core.config import Config
from core.ast_engine import ASTEngine
from utils.logger import get_logger
from utils.helpers import detect_language

class StaticMemoryAnalyzer:
    """静态内存分析器，用于检测代码中的可疑内存操作和 Shellcode"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = get_logger()
        self.ast_engine = ASTEngine()
        
        # 移植自开源社区的高质量规则
        # 可疑的内存操作模式
        self.suspicious_memory_patterns = [
            {
                'pattern': r'ctypes\.create_string_buffer',
                'title': '创建字符串缓冲区',
                'severity': 'medium',
                'description': '检测到使用ctypes创建字符串缓冲区，可能用于内存注入',
                'category': 'memory_static'
            },
            {
                'pattern': r'VirtualAlloc|mmap|allocate.*memory',
                'title': '内存分配操作',
                'severity': 'medium',
                'description': '检测到直接的内存分配 API 调用，尤其是可能用于执行代码的内存',
                'category': 'memory_static'
            },
            {
                'pattern': r'PAGE_EXECUTE|PROT_EXEC|executable.*memory',
                'title': '可执行内存设置',
                'severity': 'high',
                'description': '检测到设置内存为可执行 (PROT_EXEC/PAGE_EXECUTE)，这是代码注入的典型特征',
                'category': 'memory_static'
            },
            {
                'pattern': r'CFUNCTYPE|function.*pointer|ctypes\.cast',
                'title': '函数指针操作',
                'severity': 'medium',
                'description': '检测到函数指针操作，可能用于转换地址并执行注入的代码',
                'category': 'memory_static'
            },
            {
                'pattern': r'RtlMoveMemory|memmove|memcpy|WriteProcessMemory',
                'title': '内存写入操作',
                'severity': 'high',
                'description': '检测到直接的内存写入 API (如 WriteProcessMemory)，通常用于进程注入',
                'category': 'memory_static'
            }
        ]
        
        # 预编译正则
        for p in self.suspicious_memory_patterns:
            p['regex'] = re.compile(p['pattern'], re.IGNORECASE)

        # 检测 Shellcode 特征 (字节码模式)
        # 注意：在文本源码扫描中，我们查找的是 \xHH 形式的转义字符串，或者 bytes([0x...])
        self.shellcode_indicators = [
            r'\\x31\\xc0',  # xor eax,eax string literal
            r'\\x50\\x68',  # push eax; push dword string literal
            r'\\xeb\\x',     # jmp short string literal
            r'\\x90{10,}',  # NOP sled (长序列 \x90)
            r'0x90,\s*0x90,\s*0x90', # C 风格数组形式的 NOP sled
            r'cd\s*80'      # int 0x80 (汇编字符串)
        ]
        self.shellcode_regexes = [re.compile(p, re.IGNORECASE) for p in self.shellcode_indicators]

    def analyze(self, files: List[str]) -> Dict[str, Any]:
        """分析文件列表中的内存操作特征"""
        all_findings = []
        for file_path in files:
            try:
                # 针对特定语言启用 AST 分析
                lang = detect_language(file_path)
                if lang in ['python', 'c', 'cpp']:
                    file_findings = self._analyze_with_ast(file_path, lang)
                else:
                    file_findings = self._analyze_file(file_path)
                all_findings.extend(file_findings)
            except Exception as e:
                self.logger.error(f"StaticMemoryAnalyzer 分析文件出错 {file_path}: {e}")
        
        return {'findings': all_findings}

    def _analyze_with_ast(self, file_path: str, lang: str) -> List[Dict[str, Any]]:
        """使用 AST 引擎进行深层语义分析"""
        findings = []
        try:
            tree = self.ast_engine.parse_file(file_path, lang)
            if not tree:
                return self._analyze_file(file_path) # Fallback to regex

            with open(file_path, 'rb') as f:
                content_bytes = f.read()

            if lang == 'python':
                findings.extend(self._scan_python_ast(tree, content_bytes, file_path))
            elif lang in ['c', 'cpp']:
                findings.extend(self._scan_c_ast(tree, content_bytes, file_path))
            
            # 同时保留部分复杂的 Shellcode 正则扫描
            findings.extend(self._analyze_file(file_path, content=content_bytes.decode('utf-8', errors='ignore')))
            
        except Exception as e:
            self.logger.error(f"AST 分析失败 {file_path}: {e}")
            findings.extend(self._analyze_file(file_path))
        
        return findings

    def _scan_python_ast(self, tree, content_bytes, file_path) -> List[Dict]:
        """专门针对 Python 的 AST 扫描：针对 ctypes 链与动态执行进行语义增强"""
        py_findings = []
        root = tree.root_node
        
        # 查找所有调用节点
        calls = self.ast_engine.find_nodes_by_type(root, 'call')
        for call in calls:
            try:
                full_call_text = call.text.decode('utf-8')
                
                # 1. 识别 ctypes 操作 (包括嵌套属性调用)
                if 'ctypes' in full_call_text:
                    # 检查是否包含危险 API 关键字
                    danger_apis = ['VirtualAlloc', 'RtlMoveMemory', 'memmove', 'memset', 'create_string_buffer', 'create_unicode_buffer']
                    if any(api in full_call_text for api in danger_apis):
                        py_findings.append({
                            'id': 'MEM-PY-CTYPES-001',
                            'title': 'Ctypes 低层内存操作 (AST)',
                            'severity': 'high',
                            'category': 'memory_static',
                            'description': f'检测到源码中使用 ctypes 显式调用内存管理 API: {full_call_text[:50]}...，这常用于直接操控进程内存空间。',
                            'recommendation': '审查 ctypes 调用的必要性，确认是否为合法的系统级操作。',
                            'file': file_path,
                            'line': call.start_point[0] + 1,
                            'matched_line': full_call_text.split('\n')[0][:100],
                            'analyzer': 'StaticMemoryAnalyzer'
                        })

                # 2. 识别 eval/exec/compile (动态代码执行)
                # 获取函数名逻辑强化：支持属性调用 例如 self.eval
                func_node = call.children[0]
                func_name_text = func_node.text.decode('utf-8')
                
                if any(x == func_name_text or func_name_text.endswith('.' + x) for x in ['eval', 'exec', 'compile']):
                    # 搜寻同文件内的敏感前置动作 (启发式关联)
                    # 如果参数包含 base64, hex, bytes 等字样
                    if any(kw in full_call_text for kw in ['fromhex', 'base64', 'bytearray', 'decode']):
                         severity = 'high'
                    elif re.search(r'\\x[0-9a-fA-F]{2}', full_call_text):
                         severity = 'high'
                    else:
                         severity = 'medium'

                    py_findings.append({
                        'id': 'MEM-PY-DYNAMIC-001',
                        'title': '动态代码执行风险 (AST)',
                        'severity': severity,
                        'category': 'memory_static',
                        'description': f'检测到使用 {func_name_text} 执行动态生成的内容。若输入不可控，可能导致内存注入或任意代码执行。',
                        'recommendation': '优先使用静态逻辑替代动态执行。必须使用时，需对输入进行极严格的白名单校验。',
                        'file': file_path,
                        'line': call.start_point[0] + 1,
                        'matched_line': full_call_text.split('\n')[0][:100],
                        'analyzer': 'StaticMemoryAnalyzer'
                    })
            except Exception as e:
                self.logger.debug(f"分析 Python AST 节点出错: {e}")
                
        return py_findings

    def _scan_c_ast(self, tree, content_bytes, file_path) -> List[Dict]:
        """针对 C/C++ 的 AST 扫描：mmap 参数与 memfd_create，以及[改进]指针逃逸分析"""
        c_findings = []
        root = tree.root_node
        
        # [FNR Fix] 简单的指针逃逸追踪 (Pointer Escape Analysis)
        # 记录不安全的指针赋值: ptr = &sensitive_var
        sensitive_pointers = set()
        
        assignments = self.ast_engine.find_nodes_by_type(root, 'assignment_expression')
        for assign in assignments:
            try:
                # 简单启发式: 查找右值为取地址符 '&' 的操作
                # 结构通常是: assignment -> right -> unary_expression -> operator '&'
                if b'&' in content_bytes[assign.start_byte:assign.end_byte]:
                     # 获取左值变量名 (非常简化，仅作演示)
                     left = assign.children[0]
                     var_name = content_bytes[left.start_byte:left.end_byte].decode('utf-8')
                     sensitive_pointers.add(var_name)
            except:
                pass

        calls = self.ast_engine.find_nodes_by_type(root, 'call_expression')
        for call in calls:
            text = call.text.decode('utf-8')
            
            # [FNR Fix] 检查函数参数是否使用了敏感指针
            # 如果敏感指针被传递给未知函数，视为潜在风险
            for ptr in sensitive_pointers:
                if ptr in text and ptr != text: # 简单的参数包含检查
                     # 排除一些常见安全函数
                     if not any(safe in text for safe in ['free', 'close', 'sizeof']):
                        c_findings.append({
                            'id': 'MEM-C-PTR-ESCAPE',
                            'title': '敏感指针逃逸 (Pointer Escape)',
                            'severity': 'medium',
                            'category': 'memory_static',
                            'description': f'变量 {ptr} 被标记为敏感指针，并被传递给函数调用，存在逃逸或被不安全修改的风险。',
                            'recommendation': '确保被调用的函数不会泄露指针或进行越界写入。',
                            'file': file_path,
                            'line': call.start_point[0] + 1,
                            'matched_line': text[:100],
                            'analyzer': 'StaticMemoryAnalyzer'
                        })
            
            # 1. 识别 mmap 映射权限
            if 'mmap' in text and 'PROT_EXEC' in text:
                c_findings.append({
                    'id': 'MEM-C-MMAP-EXEC',
                    'title': '可执行内存映射 (AST)',
                    'severity': 'critical',
                    'category': 'memory_static',
                    'description': '检测到 mmap 调用中包含 PROT_EXEC 标志，程序正在尝试申请可执行内存区域。',
                    'recommendation': '避免申请同时具备写和执行权限的内存 (W^X 策略)。',
                    'file': file_path,
                    'line': call.start_point[0] + 1,
                    'matched_line': text[:100],
                    'analyzer': 'StaticMemoryAnalyzer'
                })

            # 2. 识别 memfd_create (无文件攻击意图)
            if 'memfd_create' in text:
                c_findings.append({
                    'id': 'MEM-C-FILELESS-INTENT',
                    'title': '无文件执行意图 (memfd)',
                    'severity': 'high',
                    'category': 'memory_static',
                    'description': '静态发现 memfd_create 调用，程序可能在运行时尝试执行内存中的匿名文件，此项发现已同步至动态监控引擎。',
                    'recommendation': '确认该无文件操作是否具有合法业务逻辑。',
                    'file': file_path,
                    'line': call.start_point[0] + 1,
                    'matched_line': text[:100],
                    'analyzer': 'StaticMemoryAnalyzer',
                    'meta': {'intent': 'fileless'}
                })
        return c_findings

    def _analyze_file(self, file_path: str, content: str = None) -> List[Dict[str, Any]]:
        """分析单个文件中的内存操作特征"""
        findings = []
        if content is None:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                self.logger.error(f"StaticMemoryAnalyzer 读取文件失败 {file_path}: {e}")
                return []

        lines = content.split('\n')
        
        # 1. 扫描可疑 API 调用
        for p in self.suspicious_memory_patterns:
            regex = p['regex']
            for i, line in enumerate(lines, 1):
                if len(line) > 1000: continue # 跳过过长的行
                if regex.search(line):
                    findings.append({
                        'id': 'MEM-STATIC-001',
                        'title': p['title'],
                        'severity': p['severity'],
                        'category': p['category'],
                        'description': p['description'],
                        'recommendation': '审查内存操作的必要性，确认是否涉及不安全的代码执行。',
                        'file': file_path,
                        'line': i,
                        'matched_line': line.strip()[:100],
                        'code_snippet': line.strip(),
                        'analyzer': 'StaticMemoryAnalyzer',
                        'type': 'static'
                    })

        # 2. 扫描 Shellcode 特征
        for i, line in enumerate(lines, 1):
            if len(line) > 2000: continue
            for regex in self.shellcode_regexes:
                match = regex.search(line)
                if match:
                    findings.append({
                        'id': 'MEM-SHELLCODE-001',
                        'title': '检测到 Shellcode 特征',
                        'severity': 'critical',
                        'category': 'memory_static',
                        'description': '代码中包含典型的 Shellcode 字节码模式 (如 XOR 解码, NOP 滑轨, 系统中断)，极可能是恶意 Payload。',
                        'recommendation': '立即隔离文件并进行人工逆向分析。',
                        'file': file_path,
                        'line': i,
                        'matched_line': line.strip()[:100],
                        'code_snippet': line.strip(),
                        'analyzer': 'StaticMemoryAnalyzer',
                        'type': 'static'
                    })
                    break # 一行只上报一次 Shellcode

        return findings
