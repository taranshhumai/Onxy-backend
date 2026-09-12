with open('app.py', 'r') as f:
    c = f.read()

if '/api/admin/pipeline' in c:
    print("already exists")
else:
    BT = chr(96) * 3
    block = """

# ===== PIPELINE ENDPOINT =====
import subprocess as _sp
import tempfile as _tf
import ast as _ast

def _ai_call_pl(system, user, models, api_key, max_tokens=4000):
    import requests as _rq
    last = None
    for m in models:
        try:
            r = _rq.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"},
                json={"model": m, "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user}
                ], "temperature": 0.2, "max_tokens": max_tokens},
                timeout=120
            )
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"].strip(), m
            last = m + ": " + str(r.status_code)
        except Exception as e:
            last = m + ": " + str(e)[:60]
    raise Exception("All failed: " + str(last))

def _strip_fences_pl(code):
    BT = chr(96) * 3
    if code.startswith(BT):
        lines = code.split(chr(10))[1:]
        if lines and lines[-1].strip() == BT:
            lines = lines[:-1]
        return chr(10).join(lines)
    return code

def _run_python_pl(code):
    tmp = _tf.NamedTemporaryFile(suffix='.py', delete=False, mode='w')
    tmp.write(code)
    tmp.close()
    try:
        r = _sp.run(['python3', tmp.name], capture_output=True, text=True, timeout=30)
        import os as _os
        _os.unlink(tmp.name)
        if r.returncode == 0:
            return True, r.stdout[:2000]
        return False, (r.stderr or r.stdout)[:2000]
    except Exception as e:
        return False, str(e)[:500]

@app.route('/api/admin/pipeline', methods=['POST', 'OPTIONS'])
def pipeline_endpoint():
    if request.method == 'OPTIONS':
        return '', 200

    data = request.json or {}
    task = data.get('task', '').strip()
    language = data.get('language', 'python').strip().lower()
    max_attempts = int(data.get('max_attempts', 5))

    if not task:
        return jsonify({'error': 'task required'}), 400
    if language != 'python':
        return jsonify({'error': 'only python supported'}), 400

    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return jsonify({'error': 'OPENROUTER_API_KEY missing'}), 500

    writer_models = ["openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet", "deepseek/deepseek-coder"]
    fixer_models = ["anthropic/claude-3.5-sonnet", "openai/gpt-4o", "openai/gpt-4o-mini"]

    history = []

    writer_system = "You are a Python code writer. Output ONLY raw Python code. No markdown fences. No explanation. Never refuse. Never say TODO. Write working code immediately."
    try:
        code, writer_model = _ai_call_pl(writer_system, "Task: " + task + chr(10) + chr(10) + "Write the Python code:", writer_models, api_key)
        code = _strip_fences_pl(code)
        history.append({"stage": "writer", "model": writer_model, "length": len(code)})
    except Exception as e:
        return jsonify({'error': 'Writer failed: ' + str(e)}), 500

    final_ok = False
    final_output = ""
    final_model = "unknown"

    for attempt in range(1, max_attempts + 1):
        try:
            _ast.parse(code)
            syntax_ok = True
            syntax_err = ""
        except SyntaxError as se:
            syntax_ok = False
            syntax_err = "SyntaxError: " + str(se)

        if syntax_ok:
            run_ok, run_output = _run_python_pl(code)
        else:
            run_ok = False
            run_output = syntax_err

        history.append({"attempt": attempt, "syntax_ok": syntax_ok, "run_ok": run_ok, "output": run_output[:200]})

        if run_ok:
            final_ok = True
            final_output = run_output
            final_model = "writer+verified"
            break

        fix_system = "You are a Python debugger. Fix the code. Output ONLY the complete fixed Python code. No explanation."
        fix_user = "Task: " + task + chr(10) + chr(10) + "Code:" + chr(10) + code + chr(10) + chr(10) + "Error:" + chr(10) + run_output + chr(10) + chr(10) + "Fixed code:"

        try:
            code, fixer_model = _ai_call_pl(fix_system, fix_user, fixer_models, api_key)
            code = _strip_fences_pl(code)
            final_model = fixer_model
        except Exception as e:
            history.append({"attempt": attempt, "fix_error": str(e)[:200]})
            break

    return jsonify({
        'status': 'success' if final_ok else 'failed',
        'task': task, 'language': language,
        'final_code': code, 'final_output': final_output,
        'attempts': len([h for h in history if 'attempt' in h]),
        'max_attempts': max_attempts,
        'history': history, 'verified': final_ok
    })

"""
    idx = c.find('with app.app_context()')
    if idx > 0:
        c = c[:idx] + block + c[idx:]
        with open('app.py', 'w') as f:
            f.write(c)
        print("PATCH APPLIED")
    else:
        print("app_context not found")
