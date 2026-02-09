/**
 * JavaScript 反混淆工具 v4.0
 * 
 * 针对 link.chunk.js 类型混淆代码的专用反混淆器
 * 
 * 处理流程:
 *   Phase 0: 预处理 - 提取常量数组、解压 LZString 字符串数组
 *   Phase 1: 内联常量数组访问 (vVBkVqI[0x0] → 0)
 *   Phase 2: 内联字符串解码函数调用 (f6Z6dsn(502) → "now")
 *   Phase 3: 合并字符串拼接 ("a" + "b" → "ab")
 *   Phase 4: 解析全局解析器 (tdTr8GF("Date") → Date)
 *   Phase 5: 清理优化 (属性简化、布尔值、十六进制还原、死代码移除)
 * 
 * 使用: node deobfuscator-v4.js <input.js>
 */

const fs = require('fs');
const path = require('path');
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const t = require('@babel/types');

// ============================================================
// LZString 解压库 (标准实现)
// ============================================================
const LZString = (function () {
    const f = String.fromCharCode;
    const keyStrBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    const baseReverseDic = {};

    function getBaseValue(alphabet, character) {
        if (!baseReverseDic[alphabet]) {
            baseReverseDic[alphabet] = {};
            for (let i = 0; i < alphabet.length; i++) {
                baseReverseDic[alphabet][alphabet.charAt(i)] = i;
            }
        }
        return baseReverseDic[alphabet][character];
    }

    return {
        decompressFromUTF16: function (input) {
            if (input == null) return "";
            if (input == "") return null;
            return this._decompress(input.length, 16384, function (index) {
                return input.charCodeAt(index) - 32;
            });
        },

        decompressFromBase64: function (input) {
            if (input == null) return "";
            if (input == "") return null;
            return this._decompress(input.length, 32, function (index) {
                return getBaseValue(keyStrBase64, input.charAt(index));
            });
        },

        _decompress: function (length, resetValue, getNextValue) {
            let dictionary = [], next, enlargeIn = 4, dictSize = 4, numBits = 3,
                entry = "", result = [], i, w, bits, resb, maxpower, power, c,
                data = { val: getNextValue(0), position: resetValue, index: 1 };

            for (i = 0; i < 3; i += 1) dictionary[i] = i;

            bits = 0;
            maxpower = Math.pow(2, 2);
            power = 1;
            while (power != maxpower) {
                resb = data.val & data.position;
                data.position >>= 1;
                if (data.position == 0) { data.position = resetValue; data.val = getNextValue(data.index++); }
                bits |= (resb > 0 ? 1 : 0) * power;
                power <<= 1;
            }

            switch (next = bits) {
                case 0:
                    bits = 0; maxpower = Math.pow(2, 8); power = 1;
                    while (power != maxpower) {
                        resb = data.val & data.position; data.position >>= 1;
                        if (data.position == 0) { data.position = resetValue; data.val = getNextValue(data.index++); }
                        bits |= (resb > 0 ? 1 : 0) * power; power <<= 1;
                    }
                    c = f(bits); break;
                case 1:
                    bits = 0; maxpower = Math.pow(2, 16); power = 1;
                    while (power != maxpower) {
                        resb = data.val & data.position; data.position >>= 1;
                        if (data.position == 0) { data.position = resetValue; data.val = getNextValue(data.index++); }
                        bits |= (resb > 0 ? 1 : 0) * power; power <<= 1;
                    }
                    c = f(bits); break;
                case 2: return "";
            }

            dictionary[3] = c;
            w = c;
            result.push(c);

            while (true) {
                if (data.index > length) return "";
                bits = 0; maxpower = Math.pow(2, numBits); power = 1;
                while (power != maxpower) {
                    resb = data.val & data.position; data.position >>= 1;
                    if (data.position == 0) { data.position = resetValue; data.val = getNextValue(data.index++); }
                    bits |= (resb > 0 ? 1 : 0) * power; power <<= 1;
                }

                switch (c = bits) {
                    case 0:
                        bits = 0; maxpower = Math.pow(2, 8); power = 1;
                        while (power != maxpower) {
                            resb = data.val & data.position; data.position >>= 1;
                            if (data.position == 0) { data.position = resetValue; data.val = getNextValue(data.index++); }
                            bits |= (resb > 0 ? 1 : 0) * power; power <<= 1;
                        }
                        dictionary[dictSize++] = f(bits); c = dictSize - 1; enlargeIn--; break;
                    case 1:
                        bits = 0; maxpower = Math.pow(2, 16); power = 1;
                        while (power != maxpower) {
                            resb = data.val & data.position; data.position >>= 1;
                            if (data.position == 0) { data.position = resetValue; data.val = getNextValue(data.index++); }
                            bits |= (resb > 0 ? 1 : 0) * power; power <<= 1;
                        }
                        dictionary[dictSize++] = f(bits); c = dictSize - 1; enlargeIn--; break;
                    case 2: return result.join('');
                }

                if (enlargeIn == 0) { enlargeIn = Math.pow(2, numBits); numBits++; }
                if (dictionary[c]) { entry = dictionary[c]; }
                else {
                    if (c === dictSize) { entry = w + w.charAt(0); }
                    else { return null; }
                }
                result.push(entry);
                dictionary[dictSize++] = w + entry.charAt(0);
                enlargeIn--;
                if (enlargeIn == 0) { enlargeIn = Math.pow(2, numBits); numBits++; }
                w = entry;
            }
        }
    };
})();

// ============================================================
// 配置和统计
// ============================================================
const CONFIG = {
    verbose: true,
    maxIterations: 10
};

let stats = {};

function resetStats() {
    stats = {
        hexNumbers: 0,
        constantArrayInlined: 0,
        stringDecoderInlined: 0,
        stringsMerged: 0,
        globalResolverInlined: 0,
        propertyAccessSimplified: 0,
        booleanSimplified: 0,
        deadCodeRemoved: 0,
        constantFolded: 0,
    };
}

function log(msg) {
    if (CONFIG.verbose) console.log(`[v4] ${msg}`);
}

// ============================================================
// Phase 0: 预处理 - 提取常量数组和 LZString 字符串
// ============================================================

/**
 * 解析 AST 节点为 JavaScript 值
 */
function nodeToValue(node) {
    if (!node) return { ok: false };
    if (t.isNumericLiteral(node)) return { ok: true, value: node.value };
    if (t.isStringLiteral(node)) return { ok: true, value: node.value };
    if (t.isBooleanLiteral(node)) return { ok: true, value: node.value };
    if (t.isNullLiteral(node)) return { ok: true, value: null };
    // !0 → true, !1 → false
    if (t.isUnaryExpression(node) && node.operator === '!' && t.isNumericLiteral(node.argument)) {
        return { ok: true, value: !node.argument.value };
    }
    // -number
    if (t.isUnaryExpression(node) && node.operator === '-' && t.isNumericLiteral(node.argument)) {
        return { ok: true, value: -node.argument.value };
    }
    // void 0 → undefined
    if (t.isUnaryExpression(node) && node.operator === 'void') {
        return { ok: true, value: undefined, isVoid: true };
    }
    return { ok: false };
}

/**
 * 将 JavaScript 值转换为 AST 节点
 */
function valueToNode(value) {
    if (value === null) return t.nullLiteral();
    if (value === undefined) return t.unaryExpression('void', t.numericLiteral(0));
    if (typeof value === 'number') {
        if (value < 0) return t.unaryExpression('-', t.numericLiteral(-value));
        return t.numericLiteral(value);
    }
    if (typeof value === 'string') return t.stringLiteral(value);
    if (typeof value === 'boolean') return t.booleanLiteral(value);
    return null;
}

/**
 * 提取常量数组 (const vVBkVqI = [...])
 * 返回 Map<arrayName, values[]>
 */
function extractConstantArrays(ast) {
    const arrays = new Map();

    traverse(ast, {
        VariableDeclarator(path) {
            if (!t.isIdentifier(path.node.id) || !t.isArrayExpression(path.node.init)) return;

            const elements = path.node.init.elements;
            if (elements.length < 10) return; // 只处理大数组

            const values = [];
            let allValid = true;

            for (const el of elements) {
                const parsed = nodeToValue(el);
                if (parsed.ok) {
                    values.push(parsed);
                } else {
                    allValid = false;
                    break;
                }
            }

            if (allValid) {
                const name = path.node.id.name;
                arrays.set(name, values);
                log(`发现常量数组: ${name} (${values.length} 个元素)`);
            }
        }
    });

    return arrays;
}

/**
 * 从代码中提取 LZString 压缩字符串并解压
 * 
 * 检测模式:
 *   (function() {
 *       var compressedVar = "压缩字符串...", localVar, resultVar;
 *       localVar = lzStringObj.decompressFromUTF16(compressedVar);
 *       resultVar = localVar.split("|");
 *       decoderFunc = function(index) { return resultVar[index]; }
 *   })();
 * 
 * 返回 { decoderFuncName, strings[] } 或 null
 */
function extractLZStringDecoder(ast, code) {
    let result = null;

    traverse(ast, {
        CallExpression(path) {
            // 查找 .decompressFromUTF16(...) 调用
            if (!t.isMemberExpression(path.node.callee)) return;
            const prop = path.node.callee.property;
            if (!t.isIdentifier(prop, { name: 'decompressFromUTF16' })) return;

            log(`发现 decompressFromUTF16 调用`);

            const arg = path.node.arguments[0];
            let compressedStr = null;

            // 参数可以是标识符(变量引用)或直接字符串
            if (t.isIdentifier(arg)) {
                // 在当前作用域中查找变量声明
                const binding = path.scope.getBinding(arg.name);
                if (binding && binding.path.isVariableDeclarator()) {
                    const init = binding.path.node.init;
                    if (t.isStringLiteral(init)) {
                        compressedStr = init.value;
                    }
                }
            } else if (t.isStringLiteral(arg)) {
                compressedStr = arg.value;
            }

            if (!compressedStr) {
                log(`  无法获取压缩字符串`);
                return;
            }

            log(`  压缩字符串长度: ${compressedStr.length}`);

            // 解压
            try {
                const decompressed = LZString.decompressFromUTF16(compressedStr);
                if (!decompressed) {
                    log(`  解压返回 null`);
                    return;
                }

                const strings = decompressed.split('|');
                log(`  解压成功: ${strings.length} 个字符串`);
                if (strings.length > 5) {
                    log(`  前5个: ${strings.slice(0, 5).map(s => JSON.stringify(s)).join(', ')}`);
                }

                // 查找解码函数: 通常在同一个 IIFE 中
                // 模式: decoderFunc = function(x) { return arrayVar[x]; }
                const parentFunc = path.getFunctionParent();
                if (!parentFunc) {
                    log(`  无法找到父函数`);
                    return;
                }

                // 遍历 IIFE 的函数体，查找 "outerVar = function(x) { return localVar[x] }" 模式
                const body = parentFunc.node.body;
                if (!t.isBlockStatement(body)) return;

                for (const stmt of body.body) {
                    // 查找 f6Z6dsn = function(x) { return xxx[x] }
                    if (t.isExpressionStatement(stmt) && t.isAssignmentExpression(stmt.expression)) {
                        const assign = stmt.expression;
                        if (t.isIdentifier(assign.left) && t.isFunctionExpression(assign.right)) {
                            const func = assign.right;
                            if (func.body.body.length === 1 && t.isReturnStatement(func.body.body[0])) {
                                const ret = func.body.body[0].argument;
                                if (t.isMemberExpression(ret) && ret.computed) {
                                    const decoderName = assign.left.name;
                                    // 检查这个标识符是否引用了外部作用域(即不是 IIFE 内部的局部变量)
                                    const binding = parentFunc.scope.getBinding(decoderName);
                                    // 如果 binding 不存在，或者 binding 所在的 scope 不是当前 IIFE 的 scope
                                    // 说明 decoderName 是在外部作用域声明的
                                    if (!binding || binding.scope !== parentFunc.scope) {
                                        result = { decoderFuncName: decoderName, strings };
                                        log(`  发现字符串解码函数: ${decoderName}`);
                                        path.stop();
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }

                // 备用方案: 使用正则在 decompressFromUTF16 之后搜索
                if (!result) {
                    const decompressIdx = code.indexOf('decompressFromUTF16');
                    if (decompressIdx >= 0) {
                        const afterCode = code.substring(decompressIdx, decompressIdx + 500);
                        // 匹配: funcName = function(x) { return y[x] }
                        const funcMatch = afterCode.match(/([a-zA-Z_$]\w*)\s*=\s*function\s*\([^)]+\)\s*\{\s*return\s+[a-zA-Z_$]\w*\s*\[\s*[a-zA-Z_$]\w*\s*\]/);
                        if (funcMatch) {
                            result = { decoderFuncName: funcMatch[1], strings };
                            log(`  通过正则找到解码函数: ${funcMatch[1]}`);
                        }
                    }
                }

                if (!result) {
                    // 最终备用: 存储为通用 key
                    result = { decoderFuncName: null, strings };
                    log(`  警告: 无法确定解码函数名，将尝试自动检测`);
                }

                path.stop();
            } catch (e) {
                log(`  解压失败: ${e.message}`);
            }
        }
    });

    return result;
}

/**
 * 如果未通过 AST 找到解码函数名，从代码中搜索
 */
function findDecoderFuncName(code) {
    // 注意: 代码中可能有多个 'decompressFromUTF16' 出现
    // 第一个通常在 LZString 库定义中，最后一个才是实际调用
    // 使用 lastIndexOf 找到实际的调用位置
    const decompressIdx = code.lastIndexOf('decompressFromUTF16');
    if (decompressIdx < 0) return null;

    log(`  regex搜索区域起始位置: ${decompressIdx}`);

    const searchRegion = code.substring(decompressIdx, decompressIdx + 1000);
    // 查找模式: funcName = function(x) { return y[x] }
    const match = searchRegion.match(/([a-zA-Z_$]\w*)\s*=\s*function\s*\(\s*([a-zA-Z_$]\w*)\s*\)\s*\{\s*return\s+([a-zA-Z_$]\w*)\s*\[\s*\2\s*\]\s*;?\s*\}/);
    if (match) {
        log(`  regex匹配成功: ${match[1]}`);
        return match[1];
    }
    log(`  regex未匹配到解码函数`);
    return null;
}

// ============================================================
// Phase 1-3: AST 转换
// ============================================================

/**
 * 内联常量数组访问
 * vVBkVqI[0x0] → 0
 */
function inlineConstantArrayAccess(ast, arrays) {
    let count = 0;
    traverse(ast, {
        MemberExpression(path) {
            if (!t.isIdentifier(path.node.object) || !path.node.computed) return;

            const arrayName = path.node.object.name;
            if (!arrays.has(arrayName)) return;

            const array = arrays.get(arrayName);
            let index = evaluateNode(path.node.property);

            if (typeof index !== 'number' || index < 0 || index >= array.length) return;

            const item = array[index];
            let replacement;

            if (item.isVoid) {
                replacement = t.unaryExpression('void', t.numericLiteral(0));
            } else {
                replacement = valueToNode(item.value);
            }

            if (replacement) {
                path.replaceWith(replacement);
                count++;
            }
        }
    });
    stats.constantArrayInlined += count;
    return count;
}

/**
 * 内联字符串解码函数调用
 * f6Z6dsn(502) → "now"
 */
function inlineStringDecoder(ast, decoderFuncName, strings) {
    let count = 0;
    traverse(ast, {
        CallExpression(path) {
            if (!t.isIdentifier(path.node.callee)) return;
            if (path.node.callee.name !== decoderFuncName) return;
            if (path.node.arguments.length !== 1) return;

            const arg = path.node.arguments[0];
            const index = evaluateNode(arg);

            if (typeof index !== 'number') return;
            if (index < 0 || index >= strings.length) return;

            const str = strings[index];
            if (typeof str === 'string') {
                path.replaceWith(t.stringLiteral(str));
                count++;
            }
        }
    });
    stats.stringDecoderInlined += count;
    return count;
}

/**
 * 合并字符串拼接和常量折叠
 * "abc" + "def" → "abcdef"
 * 2 + 3 → 5
 */
function foldConstantsAndMergeStrings(ast) {
    let count = 0;
    traverse(ast, {
        BinaryExpression: {
            exit(path) {
                const result = evaluateNode(path.node);
                if (result === undefined) return;

                let replacement;
                if (typeof result === 'string') {
                    replacement = t.stringLiteral(result);
                } else if (typeof result === 'number' && isFinite(result)) {
                    replacement = valueToNode(result);
                } else if (typeof result === 'boolean') {
                    replacement = t.booleanLiteral(result);
                }

                if (replacement) {
                    path.replaceWith(replacement);
                    count++;
                }
            }
        }
    });
    stats.stringsMerged += count;
    stats.constantFolded += count;
    return count;
}

/**
 * 求值表达式节点
 */
function evaluateNode(node) {
    try {
        if (t.isNumericLiteral(node)) return node.value;
        if (t.isStringLiteral(node)) return node.value;
        if (t.isBooleanLiteral(node)) return node.value;
        if (t.isNullLiteral(node)) return null;

        if (t.isUnaryExpression(node)) {
            const arg = evaluateNode(node.argument);
            if (arg === undefined && !t.isNumericLiteral(node.argument)) return undefined;
            switch (node.operator) {
                case '-': return typeof arg === 'number' ? -arg : undefined;
                case '+': return typeof arg === 'number' ? +arg : undefined;
                case '!': return !arg;
                case '~': return typeof arg === 'number' ? ~arg : undefined;
                case 'void': return undefined;
            }
        }

        if (t.isBinaryExpression(node)) {
            const left = evaluateNode(node.left);
            const right = evaluateNode(node.right);
            if (left === undefined && right === undefined) return undefined;

            // 字符串拼接特殊处理
            if (node.operator === '+') {
                if (typeof left === 'string' && typeof right === 'string') return left + right;
                if (typeof left === 'string' && typeof right === 'number') return left + right;
                if (typeof left === 'number' && typeof right === 'string') return left + right;
                if (typeof left === 'number' && typeof right === 'number') return left + right;
                return undefined;
            }

            if (typeof left !== 'number' || typeof right !== 'number') return undefined;

            switch (node.operator) {
                case '-': return left - right;
                case '*': return left * right;
                case '/': return right !== 0 ? left / right : undefined;
                case '%': return right !== 0 ? left % right : undefined;
                case '**': return left ** right;
                case '&': return left & right;
                case '|': return left | right;
                case '^': return left ^ right;
                case '<<': return left << right;
                case '>>': return left >> right;
                case '>>>': return left >>> right;
            }
        }

        return undefined;
    } catch (e) {
        return undefined;
    }
}

// ============================================================
// Phase 4: 全局解析器还原
// ============================================================

/**
 * 从已经部分还原的 AST 中提取全局解析器函数映射
 * 
 * 模式:
 *   function tdTr8GF(arg) {
 *     switch(arg) {
 *       case "SomeName": return ikNcPTY["PropertyName"];  // 或 ikNcPTY.PropertyName
 *       case "AnotherName": return ikNcPTY["AnotherProp"];
 *     }
 *   }
 * 
 * 返回 { funcName, mapping: { caseKey → propertyName } }
 */
function extractGlobalResolver(ast) {
    const resolvers = [];

    traverse(ast, {
        FunctionDeclaration(path) {
            const resolver = tryExtractResolver(path.node, path.node.id?.name);
            if (resolver) resolvers.push(resolver);
        },
        VariableDeclarator(path) {
            if (t.isFunctionExpression(path.node.init) && t.isIdentifier(path.node.id)) {
                const resolver = tryExtractResolver(path.node.init, path.node.id.name);
                if (resolver) resolvers.push(resolver);
            }
        }
    });

    return resolvers;
}

function tryExtractResolver(funcNode, funcName) {
    if (!funcNode || !funcName || !funcNode.body?.body) return null;

    for (const stmt of funcNode.body.body) {
        if (!t.isSwitchStatement(stmt)) continue;

        const mapping = {};
        let validCases = 0;

        for (const switchCase of stmt.cases) {
            if (!switchCase.test || !t.isStringLiteral(switchCase.test)) continue;

            const key = switchCase.test.value;

            for (const caseStmt of switchCase.consequent) {
                if (!t.isReturnStatement(caseStmt) || !caseStmt.argument) continue;

                const returnNode = caseStmt.argument;
                let propName = null;

                // return obj["PropertyName"] 或 return obj.PropertyName
                if (t.isMemberExpression(returnNode)) {
                    if (t.isStringLiteral(returnNode.property)) {
                        propName = returnNode.property.value;
                    } else if (t.isIdentifier(returnNode.property) && !returnNode.computed) {
                        propName = returnNode.property.name;
                    }
                }
                // return Identifier
                else if (t.isIdentifier(returnNode)) {
                    propName = returnNode.name;
                }

                if (propName) {
                    mapping[key] = propName;
                    validCases++;
                }
                break;
            }
        }

        if (validCases >= 5) {
            log(`发现全局解析器: ${funcName} (${validCases} 个映射)`);
            return { funcName, mapping };
        }
    }

    return null;
}

// 已知的全局对象/函数名
const KNOWN_GLOBALS = new Set([
    'Object', 'Array', 'String', 'Number', 'Boolean', 'Function', 'Symbol',
    'Date', 'RegExp', 'Error', 'TypeError', 'RangeError', 'SyntaxError', 'ReferenceError',
    'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Proxy', 'Reflect',
    'ArrayBuffer', 'DataView', 'SharedArrayBuffer',
    'Int8Array', 'Uint8Array', 'Uint8ClampedArray',
    'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array',
    'Float32Array', 'Float64Array', 'BigInt64Array', 'BigUint64Array',
    'TextEncoder', 'TextDecoder', 'URL', 'URLSearchParams',
    'Blob', 'File', 'FileReader', 'FormData',
    'Request', 'Response', 'Headers', 'AbortController',
    'XMLHttpRequest', 'fetch',
    'WebSocket', 'EventSource', 'BroadcastChannel',
    'Worker', 'SharedWorker', 'ServiceWorker',
    'crypto', 'Crypto', 'SubtleCrypto', 'CryptoKey',
    'performance', 'Performance', 'PerformanceObserver',
    'navigator', 'Navigator',
    'location', 'Location',
    'history', 'History',
    'localStorage', 'sessionStorage', 'Storage',
    'indexedDB', 'IDBFactory',
    'console', 'Console',
    'document', 'Document', 'window', 'Window',
    'self', 'globalThis', 'global',
    'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
    'requestAnimationFrame', 'cancelAnimationFrame',
    'queueMicrotask',
    'atob', 'btoa', 'eval', 'isNaN', 'isFinite', 'parseInt', 'parseFloat',
    'encodeURI', 'decodeURI', 'encodeURIComponent', 'decodeURIComponent',
    'JSON', 'Math', 'Intl', 'Atomics',
    'NaN', 'Infinity', 'undefined',
    'structuredClone',
    // Node.js globals
    'process', 'Buffer', 'require', 'module', 'exports', '__dirname', '__filename',
]);

/**
 * 内联全局解析器调用
 * tdTr8GF("Date") → Date
 */
function inlineGlobalResolver(ast, resolvers) {
    let count = 0;

    for (const { funcName, mapping } of resolvers) {
        traverse(ast, {
            CallExpression(path) {
                if (!t.isIdentifier(path.node.callee, { name: funcName })) return;
                if (path.node.arguments.length !== 1) return;

                const arg = path.node.arguments[0];
                if (!t.isStringLiteral(arg)) return;

                const key = arg.value;
                const globalName = mapping[key];

                if (globalName && KNOWN_GLOBALS.has(globalName)) {
                    path.replaceWith(t.identifier(globalName));
                    count++;
                }
            }
        });
    }

    stats.globalResolverInlined += count;
    return count;
}

// ============================================================
// Phase 5: 清理优化
// ============================================================

/**
 * 综合清理: 十六进制还原、属性简化、布尔值简化等
 */
function cleanupTransforms(ast) {
    traverse(ast, {
        // 十六进制数字还原
        NumericLiteral(path) {
            if (path.node.extra && path.node.extra.raw && path.node.extra.raw.startsWith('0x')) {
                delete path.node.extra.raw;
                stats.hexNumbers++;
            }
        },

        // 字符串转义还原
        StringLiteral(path) {
            if (path.node.extra) {
                delete path.node.extra.raw;
                delete path.node.extra.rawValue;
            }
        },

        // 属性访问简化: obj["prop"] → obj.prop
        MemberExpression(path) {
            if (!path.node.computed) return;

            const prop = path.node.property;
            if (t.isStringLiteral(prop)) {
                const propName = prop.value;
                if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName) && !isReservedWord(propName)) {
                    path.node.computed = false;
                    path.node.property = t.identifier(propName);
                    stats.propertyAccessSimplified++;
                }
            }

            // 逗号表达式简化: obj[("", "prop")] → obj.prop
            if (t.isSequenceExpression(prop)) {
                const last = prop.expressions[prop.expressions.length - 1];
                if (t.isStringLiteral(last)) {
                    const propName = last.value;
                    if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName) && !isReservedWord(propName)) {
                        path.node.computed = false;
                        path.node.property = t.identifier(propName);
                    } else {
                        path.node.property = last;
                    }
                    stats.propertyAccessSimplified++;
                }
            }
        },

        // 布尔值简化: !0 → true, !1 → false
        UnaryExpression: {
            exit(path) {
                if (path.node.operator === '!' && t.isNumericLiteral(path.node.argument)) {
                    path.replaceWith(t.booleanLiteral(!path.node.argument.value));
                    stats.booleanSimplified++;
                }
            }
        },

        // 条件表达式简化
        ConditionalExpression: {
            exit(path) {
                if (t.isBooleanLiteral(path.node.test)) {
                    path.replaceWith(path.node.test.value ? path.node.consequent : path.node.alternate);
                    stats.deadCodeRemoved++;
                }
            }
        },

        // if 语句简化
        IfStatement: {
            exit(path) {
                if (t.isBooleanLiteral(path.node.test)) {
                    if (path.node.test.value) {
                        if (t.isBlockStatement(path.node.consequent)) {
                            path.replaceWithMultiple(path.node.consequent.body);
                        } else {
                            path.replaceWith(path.node.consequent);
                        }
                    } else {
                        if (path.node.alternate) {
                            if (t.isBlockStatement(path.node.alternate)) {
                                path.replaceWithMultiple(path.node.alternate.body);
                            } else {
                                path.replaceWith(path.node.alternate);
                            }
                        } else {
                            path.remove();
                        }
                    }
                    stats.deadCodeRemoved++;
                }
            }
        },

        // 逻辑表达式简化
        LogicalExpression: {
            exit(path) {
                const { left, right, operator } = path.node;
                if (t.isBooleanLiteral(left)) {
                    if (operator === '&&') {
                        path.replaceWith(left.value ? right : t.booleanLiteral(false));
                        stats.constantFolded++;
                    } else if (operator === '||') {
                        path.replaceWith(left.value ? t.booleanLiteral(true) : right);
                        stats.constantFolded++;
                    }
                }
            }
        },

        // 空语句移除
        EmptyStatement(path) {
            path.remove();
        }
    });
}

function isReservedWord(name) {
    const reserved = new Set([
        'break', 'case', 'catch', 'continue', 'debugger', 'default', 'delete',
        'do', 'else', 'finally', 'for', 'function', 'if', 'in', 'instanceof',
        'new', 'return', 'switch', 'this', 'throw', 'try', 'typeof', 'var',
        'void', 'while', 'with', 'class', 'const', 'enum', 'export', 'extends',
        'import', 'super', 'implements', 'interface', 'let', 'package', 'private',
        'protected', 'public', 'static', 'yield'
    ]);
    return reserved.has(name);
}

// ============================================================
// 主流程
// ============================================================

function deobfuscate(code, filename = 'unknown') {
    log('============================================================');
    log(`处理文件: ${filename}`);
    log('============================================================');
    log(`代码长度: ${code.length} 字符`);

    resetStats();

    // Phase 0: 解析 AST
    log('\nPhase 0: 解析 AST 并提取数据...');
    const ast = parser.parse(code, {
        sourceType: 'unambiguous',
        plugins: ['jsx'],
        errorRecovery: true,
    });

    // 提取常量数组
    const constantArrays = extractConstantArrays(ast);

    // 提取 LZString 解压后的字符串数组
    let lzResult = extractLZStringDecoder(ast, code);
    let decoderFuncName = lzResult?.decoderFuncName;
    let decodedStrings = lzResult?.strings;

    // 如果未通过 AST 找到解码函数名，尝试正则
    if (decodedStrings && !decoderFuncName) {
        decoderFuncName = findDecoderFuncName(code);
        if (decoderFuncName) {
            log(`通过正则补充找到解码函数: ${decoderFuncName}`);
        }
    }

    if (!decodedStrings) {
        log('警告: 未找到 LZString 压缩字符串，尝试其他检测方式...');

        // 备用方案: 使用通用正则匹配 decompressFromUTF16
        const genericPattern = /(\w+)\.decompressFromUTF16\s*\(\s*(\w+)\s*\)/;
        const match = code.match(genericPattern);
        if (match) {
            log(`  发现通用解压模式: ${match[1]}.decompressFromUTF16(${match[2]})`);

            // 尝试找到压缩字符串变量
            const varName = match[2];
            // 使用 AST 查找该变量的值
            traverse(ast, {
                VariableDeclarator(path) {
                    if (t.isIdentifier(path.node.id, { name: varName }) && t.isStringLiteral(path.node.init)) {
                        try {
                            const decompressed = LZString.decompressFromUTF16(path.node.init.value);
                            if (decompressed) {
                                decodedStrings = decompressed.split('|');
                                log(`  备用方案解压成功: ${decodedStrings.length} 个字符串`);
                            }
                        } catch (e) {
                            log(`  备用方案解压失败: ${e.message}`);
                        }
                    }
                }
            });

            if (decodedStrings && !decoderFuncName) {
                decoderFuncName = findDecoderFuncName(code);
            }
        }
    }

    log(`\n数据提取结果:`);
    log(`  常量数组: ${constantArrays.size} 个`);
    log(`  字符串解码函数: ${decoderFuncName || '未找到'}`);
    log(`  解码字符串: ${decodedStrings ? decodedStrings.length + ' 个' : '未找到'}`);

    // Phase 1: 内联常量数组
    log('\nPhase 1: 内联常量数组访问...');
    let changed = true;
    let iterations = 0;

    while (changed && iterations < CONFIG.maxIterations) {
        iterations++;
        changed = false;

        const arrayCount = inlineConstantArrayAccess(ast, constantArrays);
        if (arrayCount > 0) {
            changed = true;
            log(`  第 ${iterations} 轮: 内联了 ${arrayCount} 个数组访问`);
        }

        // 同时做常量折叠
        const foldCount = foldConstantsAndMergeStrings(ast);
        if (foldCount > 0) changed = true;
    }
    log(`  总计内联: ${stats.constantArrayInlined} 个数组访问`);

    // Phase 2: 内联字符串解码函数
    if (decoderFuncName && decodedStrings) {
        log('\nPhase 2: 内联字符串解码函数...');
        changed = true;
        iterations = 0;

        while (changed && iterations < CONFIG.maxIterations) {
            iterations++;
            changed = false;

            const decoderCount = inlineStringDecoder(ast, decoderFuncName, decodedStrings);
            if (decoderCount > 0) {
                changed = true;
                log(`  第 ${iterations} 轮: 内联了 ${decoderCount} 个解码调用`);
            }

            // 继续内联常量数组(可能有嵌套)
            const arrayCount = inlineConstantArrayAccess(ast, constantArrays);
            if (arrayCount > 0) changed = true;
        }
        log(`  总计内联: ${stats.stringDecoderInlined} 个解码调用`);
    } else {
        log('\nPhase 2: 跳过 (无字符串解码函数)');
    }

    // Phase 3: 字符串拼接合并
    log('\nPhase 3: 合并字符串拼接...');
    changed = true;
    iterations = 0;

    while (changed && iterations < CONFIG.maxIterations) {
        iterations++;
        const prevMerged = stats.stringsMerged;
        foldConstantsAndMergeStrings(ast);
        changed = stats.stringsMerged > prevMerged;
    }
    log(`  合并了 ${stats.stringsMerged} 处字符串拼接/常量折叠`);

    // Phase 4: 全局解析器还原
    log('\nPhase 4: 解析全局解析器...');
    const resolvers = extractGlobalResolver(ast);
    if (resolvers.length > 0) {
        // 可能需要多轮
        changed = true;
        iterations = 0;
        while (changed && iterations < 3) {
            iterations++;
            const prevCount = stats.globalResolverInlined;
            inlineGlobalResolver(ast, resolvers);
            changed = stats.globalResolverInlined > prevCount;
        }
        log(`  还原了 ${stats.globalResolverInlined} 个全局解析器调用`);
    } else {
        log('  未找到全局解析器函数');
    }

    // Phase 5: 清理优化
    log('\nPhase 5: 清理优化...');
    cleanupTransforms(ast);

    // 最终一轮常量折叠
    foldConstantsAndMergeStrings(ast);

    // 生成代码
    log('\n生成最终代码...');
    const output = generate(ast, {
        comments: true,
        jsescOption: {
            minimal: true,
            quotes: 'double',
        }
    });

    // 打印统计
    log('\n============================================================');
    log('处理统计:');
    log(`  十六进制数字还原: ${stats.hexNumbers}`);
    log(`  常量数组内联: ${stats.constantArrayInlined}`);
    log(`  字符串解码内联: ${stats.stringDecoderInlined}`);
    log(`  字符串/常量合并: ${stats.stringsMerged}`);
    log(`  全局解析器还原: ${stats.globalResolverInlined}`);
    log(`  属性访问简化: ${stats.propertyAccessSimplified}`);
    log(`  布尔值简化: ${stats.booleanSimplified}`);
    log(`  死代码移除: ${stats.deadCodeRemoved}`);
    log('============================================================');

    return output.code;
}

// ============================================================
// CLI
// ============================================================

function processFile(inputPath) {
    const filename = path.basename(inputPath);
    const dirname = path.dirname(inputPath);
    const ext = path.extname(filename);
    const basename = path.basename(filename, ext);
    const outputPath = path.join(dirname, `${basename}_deobfuscated_v4${ext}`);

    const code = fs.readFileSync(inputPath, 'utf-8');
    const result = deobfuscate(code, filename);

    fs.writeFileSync(outputPath, result, 'utf-8');

    log(`\n输出文件: ${outputPath}`);
    log(`原始大小: ${code.length} 字符`);
    log(`处理后大小: ${result.length} 字符`);

    return outputPath;
}

function main() {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log(`
JavaScript 反混淆工具 v4.0
========================================

专门针对 link.chunk.js 类型混淆代码

核心功能:
  1. 常量数组内联 (arr[0x1f] → 31)
  2. LZString 解压 + 字符串解码内联 (decoder(502) → "now")
  3. 字符串拼接合并 ("abc" + "def" → "abcdef")
  4. 全局解析器还原 (resolver("Date") → Date)
  5. 属性访问简化 (obj["prop"] → obj.prop)
  6. 十六进制还原、布尔值简化、死代码移除

使用方法:
  node deobfuscator-v4.js <input.js>

示例:
  node deobfuscator-v4.js link.chunk.js
        `);
        return;
    }

    console.log('\n========================================');
    console.log('   JavaScript 反混淆工具 v4.0');
    console.log('========================================\n');

    const outputFiles = [];

    for (const inputFile of args) {
        const inputPath = path.resolve(inputFile);

        if (!fs.existsSync(inputPath)) {
            console.error(`文件不存在: ${inputPath}`);
            continue;
        }

        try {
            const outputPath = processFile(inputPath);
            outputFiles.push(outputPath);
        } catch (error) {
            console.error(`处理失败: ${inputFile}`);
            console.error(error);
        }
    }

    console.log('\n========================================');
    console.log('处理完成!');
    console.log('========================================');
    console.log('\n生成的文件:');
    outputFiles.forEach(f => console.log(`  - ${f}`));
}

module.exports = { deobfuscate, processFile, LZString };

if (require.main === module) {
    main();
}
