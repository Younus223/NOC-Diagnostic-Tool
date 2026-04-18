from flask import Flask, render_template, request, Response, stream_with_context, send_file
from network_engine import NetworkDiagnostic, get_accurate_ping 
import os
import requests
import sys
import webbrowser
from threading import Timer

# --- تعديل 1: دالة لتحديد المسارات الصحيحة داخل ملف الـ EXE ---
def resource_path(relative_path):
    """ الحصول على المسار المطلق للملفات، يعمل في التطوير وفي ملف EXE """
    try:
        # مجلد PyInstaller المؤقت _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- تعديل 2: تهيئة Flask مع تحديد مجلد الـ templates المسار الصحيح ---
app = Flask(__name__, template_folder=resource_path('templates'))
diag = NetworkDiagnostic() 

def get_ip_info(ip):
    try:
        if ip.startswith(('192.', '10.', '172.', '127.')):
            return "الشبكة المحلية (Local Network)"
        
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=city,country,isp", timeout=2)
        data = response.json()
        if data.get('status') == 'success':
            return f"{data['city']}, {data['country']} ({data['isp']})"
    except:
        pass
    return "موقع غير معروف (Unknown Location)"

# 1. الصفحة الرئيسية
@app.route('/')
def index():
    return render_template('index.html', results=None)

# 2. مسار الفحص الشامل المحدث
@app.route('/diagnose', methods=['POST'])
def diagnose():
    target = request.form.get('target_ip', '8.8.8.8')
    if target == 'custom':
        target = request.form.get('gateway', '192.168.1.1')
    
    results = diag.run_all_tests(target)
    ping_result = get_accurate_ping(target)
    results['tests']['Gateway']['lat'] = ping_result
    
    devices_list = diag.scan_network()
    location_info = get_ip_info(target)
    
    analysis = f"✅ الفحص يستهدف: {target} | الموقع: {location_info}"
    
    try:
        latency_value = float(ping_result)
        if not results['tests']['Internet']['status']:
            analysis = "❌ لا يوجد اتصال بالإنترنت، يرجى التحقق من الكابلات أو مزود الخدمة."
        elif latency_value > 50:
            analysis = "⚠️ تأخير مرتفع في الشبكة المحلية! قد تواجه بطئاً؛ جرب الانتقال لمكان أقرب للراوتر."
        elif float(results['tests']['Gateway']['jitter']) > 10:
            analysis = "⚠️ تم رصد تذبذب (Jitter)؛ قد يؤثر هذا على جودة الاتصال."
    except ValueError:
        analysis = "⚠️ تعذر تحليل زمن الاستجابة بدقة."

    return render_template('index.html', 
                           results=results, 
                           devices_list=devices_list, 
                           analysis=analysis)

# 3. مسارات البث (Traceroute & Ports)
@app.route('/stream_trace')
def stream_trace():
    target = request.args.get('target', '8.8.8.8')
    return Response(stream_with_context(diag.stream_traceroute(target)), mimetype='text/event-stream')

@app.route('/stream_ports')
def stream_ports():
    target_ip = request.args.get('target')
    return Response(stream_with_context(diag.scan_ports(target_ip)), mimetype='text/event-stream')

# 4. مسار التقارير والتحميل
@app.route('/download_report', methods=['POST'])
def download_report():
    target = request.form.get('target_ip', '192.168.1.1')
    results = diag.run_all_tests(target)
    devices_list = diag.scan_network()
    filename = diag.generate_report(results, devices_list)
    return send_file(filename, as_attachment=True)

@app.route('/download_exe')
def download_exe():
    path = "NOC_Tool.exe"
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    else:
        return "النسخة المكتبية قيد التجهيز، يرجى المحاولة لاحقاً.", 404

# --- تعديل 3: دالة لفتح المتصفح تلقائياً ---
def open_browser():
    """ يفتح المتصفح على العنوان المحلي للبرنامج """
    webbrowser.open_new('http://127.0.0.1:5000/')

if __name__ == '__main__':
    # في حالة التشغيل العادي أو EXE، نفتح المتصفح بعد ثانية واحدة
    if not os.environ.get("WERKZEUG_RUN_MAIN"): # لضمان عدم الفتح مرتين في وضع Debug
        Timer(1, open_browser).start()
    
    # تشغيل السيرفر
    # ملاحظة: 0.0.0.0 تسمح بالوصول من الشبكة، و 127.0.0.1 هي الأكثر أماناً للـ EXE
    app.run(host='0.0.0.0', port=5000)