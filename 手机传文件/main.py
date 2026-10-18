from bottle import route,run,static_file,abort,redirect,response,request
import os
import hashlib
import zipfile
import io
import mimetypes
import socket
import time
import time_random

#=====================配置项=====================
SAFE_ROOT="/storage/emulated/0"
BLOCK_DIRS={"Android/data","Android/obb"}
RAW_PWD_HASH="c4c9509e74a813a922eee8163ac052c1340f4907ace4da5785f9ba3027e1b8b7"
PORT=2026
LISTEN_HOST="0.0.0.0"
ZIP_OVER_SIZE=50*1024*1024
SESSION_DIR="sessions"
SESSION_MAX_AGE=7*24*3600
#==================================================

if not os.path.isdir(SESSION_DIR):
	os.makedirs(SESSION_DIR,exist_ok=True)

def sweep_expired_sessions():
	now=time.time()
	for fname in os.listdir(SESSION_DIR):
		fpath=os.path.join(SESSION_DIR,fname)
		if not os.path.isfile(fpath):
			continue
		try:
			with open(fpath,"r",encoding="utf-8") as f:
				ts=float(f.read().strip())
			if now-ts>SESSION_MAX_AGE:
				os.unlink(fpath)
		except:
			pass

def is_session_valid(sess_name:str)->bool:
	sweep_expired_sessions()
	spath=os.path.join(SESSION_DIR,sess_name)
	if not os.path.isfile(spath):
		return False
	try:
		with open(spath,"r",encoding="utf-8") as f:
			ts=float(f.read().strip())
		return time.time()-ts<=SESSION_MAX_AGE
	except:
		return False

def create_session()->str:
	sess_name=time_random.time_random()
	spath=os.path.join(SESSION_DIR,sess_name)
	with open(spath,"w",encoding="utf-8") as f:
		f.write(str(time.time()))
	return sess_name

def destroy_session(sess_name:str):
	spath=os.path.join(SESSION_DIR,sess_name)
	if os.path.isfile(spath):
		try:
			os.unlink(spath)
		except:
			pass

def get_lan_ip():
	try:
		s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		s.connect(("1.1.1.1",80))
		ip=s.getsockname()[0]
		s.close()
		return ip
	except:
		return None

def require_login(func):
	def wrapper(*args,**kwargs):
		sess=request.get_cookie("session_id",default="")
		if not is_session_valid(sess):
			return redirect("/login")
		return func(*args,**kwargs)
	return wrapper

def set_utf8_header():
	response.content_type="text/html; charset=utf-8"

def get_safe_full_path(req_path):
	raw_path=req_path.lstrip("/")
	full=os.path.abspath(os.path.join(SAFE_ROOT,raw_path))
	root_abs=os.path.abspath(SAFE_ROOT)
	if full !=root_abs and not full.startswith(root_abs+os.sep):
		abort(403,"禁止跨目录访问")
	for block in BLOCK_DIRS:
		b_path=os.path.abspath(os.path.join(SAFE_ROOT,block))
		if full.startswith(b_path+os.sep) or full==b_path:
			abort(403,"应用私有数据禁止访问")
	return full

def guess_view_mode(filename):
	fn=filename.lower()
	ext=os.path.splitext(fn)[1]
	img_exts={".jpg",".jpeg",".png",".gif",".bmp",".webp",".svg"}
	vid_exts={".mp4",".webm",".ogg",".mov",".m4v"}
	aud_exts={".mp3",".wav",".flac",".ogg",".m4a"}
	txt_exts={".txt",".md",".py",".js",".css",".json",".xml",".ini",".log",".csv",".sh",".bat"}
	pdf_exts={".pdf",".html"}
	if ext in img_exts:return "image"
	if ext in vid_exts:return "video"
	if ext in aud_exts:return "audio"
	if ext in txt_exts:return "text"
	if ext in pdf_exts:return "pdf"
	return "hex"

@route("/")
def index():
	sess=request.get_cookie("session_id",default="")
	if is_session_valid(sess):
		return redirect("/list")
	return redirect("/login")

@route("/logout")
def logout():
	sess=request.get_cookie("session_id",default="")
	destroy_session(sess)
	response.set_cookie("session_id","",expires=0)
	return redirect("/login")

@route("/zipdownload/<req_path:path>")
@require_login
def zip_download(req_path):
	target_path=get_safe_full_path(req_path)
	buf=io.BytesIO()
	with zipfile.ZipFile(buf,"w",zipfile.ZIP_DEFLATED) as zf:
		if os.path.isdir(target_path):
			base_name=os.path.basename(target_path)
			for root,dirs,files in os.walk(target_path):
				for name in files:
					file_full=os.path.join(root,name)
					arcname=os.path.relpath(file_full,target_path)
					zf.write(file_full,os.path.join(base_name,arcname))
		elif os.path.isfile(target_path):
			base_name=os.path.basename(target_path)
			zf.write(target_path,base_name)
		else:
			abort(400,"目标不存在")
	buf.seek(0)
	if os.path.isdir(target_path):
		zipname=os.path.basename(target_path)+".zip"
	else:
		zipname=os.path.basename(target_path)+".zip"
	response.headers["Content-Type"]="application/zip"
	response.headers["Content-Disposition"]=f'attachment; filename="{zipname}"'
	return buf.read()

@route("/login")
def login_page():
	set_utf8_header()
	html="""
<html>
	<head>
		<meta charset="utf-8">
<title>身份验证</title>
		<style>
			.box{width:320px;margin:80px auto;}
			input{width:100%;margin:8px 0;padding:10px;box-sizing:border-box;font-size:16px}
			button{width:100%;padding:12px;background:#007bff;color:#fff;border:none;border-radius:4px}
		</style>
	</head>
	<body>
		<div class="box">
			<h3>文件服务器登录验证</h3>
			<form method="post" action="/dologin" accept‑charset="UTF‑8">
				<input type="password" name="pwd" maxlength="20" placeholder="输入登录密码">
				<button type="submit">确认登录</button>
			</form>
		</div>
	</body>
</html>
"""
	return html

@route("/dologin",method="POST")
def do_login():
	client=request.forms.get("pwd","")
	client_hash=hashlib.sha256(client.encode("utf-8")).hexdigest()
	print("clt:",client.encode("utf-8"))
	print("clt hash:",client_hash)
	print("raw hash:",RAW_PWD_HASH)
	if client_hash==RAW_PWD_HASH:
		sess_name=create_session()
		response.set_cookie("session_id",sess_name,max_age=86400*7,httponly=True)
		return redirect("/list")
	return '<h3>密码错误</h3><a href="/login">返回登录</a>'

@route('/list')
@route('/list/')
@route('/list/<req_path:path>')
@require_login
def list_dir(req_path=""):
	set_utf8_header()
	try:
		full_path=get_safe_full_path(req_path)
	except Exception as e:
		return f"<h3>路径解析错误：{str(e)}</h3>"

	if not os.path.isdir(full_path):
		abort(404,"文件夹不存在")

	path_arr=[i for i in req_path.split("/") if i]
	parent_path="/".join(path_arr[:-1]) if path_arr else ""
	parent_url=f"/list/{parent_path}" if parent_path else "/list"

	html='''
<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width,initial-scale=1.0">
		<title>文件管理器</title>
		<style>
			*{margin:0;padding:0;box-sizing:border-box;}
			body{font-size:15px;padding:15px;}
			.back-item{padding:10px 8px;margin:6px 0;border:1px solid #ccc;border-radius:6px;background:#e8f4ff;text-decoration:none;color:#000;display:block;}
			.item{margin:6px 0;padding:10px 8px;border:1px solid #ccc;border-radius:6px;user-select:none;}
			.folder{background:#e8f4ff}
			.file{background:#ffffff}
			.logout{float:right;padding:6px 10px;background:#f44;color:#fff;text-decoration:none;border-radius:4px;}
		</style>
	</head>
	<body>
		<a href="/logout" class="logout">退出登录</a>
'''
	html +=f"		<h3>当前目录：{SAFE_ROOT}/{req_path}</h3><br>"
	html +=f'		<a href="{parent_url}" class="back-item">← 返回上级目录</a>'

	dir_list=[]
	file_list=[]
	try:
		items=os.listdir(full_path)
	except PermissionError:
		html +="		<p style='color:red;margin-top:12px'>⚠ 当前目录权限被系统拦截，无法读取</p>"
		return html + """
	</body>
</html>
"""

	for name in items:
		rel_item=os.path.join(req_path,name).lstrip("/")
		skip=False
		for b in BLOCK_DIRS:
			b_rel=b
			if rel_item.startswith(b_rel+"/") or rel_item==b_rel:
				skip=True
				break
		if skip:
			continue
		item_full=os.path.join(full_path,name)
		if os.path.isdir(item_full):
			dir_list.append((name,rel_item,True))
		else:
			file_list.append((name,rel_item,False))

	for name,rel,isdir in sorted(dir_list):
		html +=f'''
		<div onclick="location.href=&quot;/list/abc'def&quot;">	
📁 {name} <a href="/zipdownload/{rel}" style="float:right">[打包下载]</a></div>
'''
	for name,rel,isdir in sorted(file_list):
		html +=f'''
<div class="item file"
	ontouchstart="touchStart(this,event,'{rel}')"
	ontouchend="touchEnd(this,event,'{rel}')"
	onmousedown="touchStart(this,event,'{rel}')"
	onmouseup="touchEnd(this,event,'{rel}')"
>📄 {name} <span style="font-size:12px;color:#888">(轻点预览 / 长按下载)</span></div>
'''

	html +='''
<script>
let longPressTimer=null;
const LONG_PRESS_MS=500;
function touchStart(dom,e,rel){
	e.preventDefault();
	longPressTimer=setTimeout(()=>{
		window.location.href="/downloadlogic/"+rel;
	},LONG_PRESS_MS);
}
function touchEnd(dom,e,rel){
	clearTimeout(longPressTimer);
	setTimeout(()=>{
		if(longPressTimer) window.location.href="/preview/"+rel;
	},10);
}
</script>
</body></html>'''
	return html

@route("/downloadlogic/<req_path:path>")
@require_login
def download_logic(req_path):
	fpath=get_safe_full_path(req_path)
	if not os.path.isfile(fpath):
		abort(404,"文件不存在")
	size=os.path.getsize(fpath)
	if size>ZIP_OVER_SIZE:
		return redirect(f"/zipdownload/{req_path}")
	else:
		return redirect(f"/download/{req_path}")

@route('/download/<req_path:path>')
@require_login
def download_file(req_path):
	full_path=get_safe_full_path(req_path)
	if not os.path.isfile(full_path):
		abort(404,"文件不存在")
	filename=os.path.basename(full_path)
	return static_file(filename,root=os.path.dirname(full_path),download=True)

@route("/preview/<req_path:path>")
@require_login
def preview_page(req_path):
	fpath=get_safe_full_path(req_path)
	if not os.path.isfile(fpath):
		abort(404,"文件不存在")
	fn=os.path.basename(fpath)
	mode=request.query.get("mode",guess_view_mode(fn))
	set_utf8_header()
	modes=[
		("auto","自动"),
		("image","图片"),
		("video","视频"),
		("audio","音频"),
		("text","文本"),
		("pdf","PDF"),
		("hex","十六进制查看"),
	]
	sel={m[0]:(m[0]==mode) for m in modes}
	html=f'''
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>预览：{fn}</title>
<style>
body{{padding:12px;font-size:15px;}}
.ctrl{{margin-bottom:12px;}}
iframe,img{{max-width:100%;border:1px solid #aaa;}}
pre{{white-space:pre-wrap;word-wrap:break-word;max-height:70vh;overflow:auto;background:#f8f8f8;padding:8px;}}
</style>
</head>
<body>
<div class="ctrl">
<a href="/list">← 返回文件列表</a>
&nbsp; <a href="/downloadlogic/{req_path}">[下载]</a>
&nbsp; <a href="/logout">[退出登录]</a>
<form style="display:inline-block;margin-left:10px">
模式：
<select name="mode" onchange="this.form.submit()">
'''
	for mval,mname in modes:
		s="selected" if sel[mval] else ""
		html+=f'<option value="{mval}" {s}>{mname}</option>'
	html+=f'''
</select>
</form>
</div>
<h4>{fn}</h4>
'''
	src_url=f"/rawfile/{req_path}"
	if mode=="image":
		html+=f'<img src="{src_url}" alt="preview">'
	elif mode=="video":
		html+=f'<video controls style="max-width:100%"><source src="{src_url}">浏览器不支持此视频</video>'
	elif mode=="audio":
		html+=f'<audio controls style="width:100%"><source src="{src_url}">浏览器不支持此音频'
	elif mode=="pdf":
		html+=f'<iframe src="{src_url}" style="width:100%;height:75vh;"></iframe>'
	elif mode=="text":
		try:
			with open(fpath,"rt",encoding="utf-8",errors="replace") as fp:
				txt=fp.read(1024*200)
			html+=f"<pre>{txt}</pre>"
		except:
			html+="<p>文本读取失败</p>"
	elif mode=="hex":
		try:
			with open(fpath,"rb") as fp:
				data=fp.read(1024*40)
			lines=[]
			for i in range(0,len(data),16):
				chunk=data[i:i+16]
				hx=" ".join(f"{b:02x}" for b in chunk)
				asc="".join(chr(b) if 32<=b<127 else "." for b in chunk)
				lines.append(f"{i:08x}  {hx:<47} |{asc}|")
			html+="<pre>"+"\n".join(lines)+"\n(仅显示前64KB)</pre>"
		except:
			html+="<p>二进制读取失败</p>"
	else:
		auto_m=guess_view_mode(fn)
		return redirect(f"/preview/{req_path}?mode={auto_m}")
	html+="</body></html>"
	return html

@route("/rawfile/<req_path:path>")
@require_login
def raw_file(req_path):
	fpath=get_safe_full_path(req_path)
	if not os.path.isfile(fpath):
		abort(404,"文件不存在")
	mime,_=mimetypes.guess_type(fpath)
	if not mime:
		mime="application/octet-stream"
	response.content_type=mime
	return static_file(os.path.basename(fpath),root=os.path.dirname(fpath))

if __name__=="__main__":
	lan_ip=get_lan_ip()
	lan_addr=f"http://{lan_ip}:{PORT}" if lan_ip else "无法检测"
	print(f"""===文件服务启动===
监听：http://{LISTEN_HOST}:{PORT}
局域网地址：{lan_addr}
会话有效期：7天
会话目录：{SESSION_DIR}/
大于 {ZIP_OVER_SIZE//1024//1024}MB 的文件下载将自动打包ZIP
仅内网使用！切勿暴露到公网！
按下Ctrl+C停止(如果使用的终端执行该操作无其他行为)""")
	run(host=LISTEN_HOST,port=PORT,quiet=False,debug=False,server="wsgiref")
