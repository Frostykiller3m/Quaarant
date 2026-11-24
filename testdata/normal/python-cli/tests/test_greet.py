import subprocess, sys

def test_greet():
    out = subprocess.run([sys.executable, '-c', 'import greet; greet.main()'], capture_output=True, text=True)
    assert out.stdout.startswith('hello')
