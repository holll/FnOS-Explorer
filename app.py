from flask import Flask, render_template, request, redirect, url_for, send_file, Response, jsonify
from database import init_db, get_all_targets, get_target_by_id, get_targets_paginated, get_status_counts, update_target_note, update_target_status_only, update_target_status_by_ip, update_target_favorite
from scanner import process_csv, import_all_csv_files, scan_pending_targets
from file_ops import get_remote_content, recursive_zip_download, build_remote_url

app = Flask(__name__)

# 初始化数据库
init_db()


def get_flag_emoji(country_code):
    """将国家代码转换为国旗 emoji"""
    if not country_code or len(country_code) != 2:
        return '🏳️'
    
    # 将国家代码转换为区域指示符号（Regional Indicator Symbols）
    # A-Z 对应 Unicode 0x1F1E6-0x1F1FF
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in country_code.upper())


def get_file_icon(filename):
    """根据文件扩展名返回对应的 emoji 图标"""
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    
    icon_map = {
        # 图片
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'bmp': '🖼️', 'svg': '🖼️', 'webp': '🖼️', 'ico': '🖼️',
        # 文档
        'pdf': '📕', 'doc': '📘', 'docx': '📘', 'xls': '📗', 'xlsx': '📗', 'ppt': '📙', 'pptx': '📙',
        # 文本
        'txt': '📝', 'log': '📋', 'md': '📝', 'json': '📋', 'xml': '📋', 'csv': '📊',
        # 代码
        'py': '🐍', 'js': '📜', 'html': '🌐', 'css': '🎨', 'java': '☕', 'c': '©️', 'cpp': '©️', 'sh': '🔧',
        # 压缩
        'zip': '📦', 'rar': '📦', 'tar': '📦', 'gz': '📦', '7z': '📦',
        # 音视频
        'mp3': '🎵', 'wav': '🎵', 'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬',
    }
    
    return icon_map.get(ext, '📄')


# 注册为模板函数
app.jinja_env.globals.update(get_flag_emoji=get_flag_emoji)
app.jinja_env.globals.update(get_file_icon=get_file_icon)
app.jinja_env.globals.update(build_remote_url=build_remote_url)


@app.route('/')
def index():
    # 获取分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    status_filter = request.args.get('status', 'Vulnerable')  # 默认筛选漏洞
    search_query = request.args.get('search', '')
    
    # 获取分页数据
    pagination = get_targets_paginated(
        page=page,
        per_page=per_page,
        status_filter=status_filter if status_filter != 'all' else None,
        search_query=search_query if search_query else None
    )
    
    # 获取状态统计
    status_counts = get_status_counts()
    
    return render_template('index.html', 
                         targets=pagination['items'],
                         pagination=pagination,
                         status_counts=status_counts,
                         current_status=status_filter,
                         search_query=search_query)


@app.route('/import', methods=['POST'])
def import_csv_route():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))

    process_csv(file)
    return redirect(url_for('index'))


@app.route('/import_all', methods=['POST'])
def import_all_route():
    """一键导入所有 CSV 文件"""
    result = import_all_csv_files()
    return jsonify(result)


@app.route('/scan_pending', methods=['POST'])
def scan_pending_route():
    """扫描所有待检查的目标"""
    # 获取线程数配置
    data = request.get_json() or {}
    max_workers = data.get('max_workers', 32)
    
    # 验证线程数范围
    if not isinstance(max_workers, int) or max_workers < 1 or max_workers > 100:
        return jsonify({"success": False, "message": "线程数必须在 1-100 之间"})
    
    result = scan_pending_targets(max_workers=max_workers)
    return jsonify(result)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """获取统计数据 API"""
    status_counts = get_status_counts()
    return jsonify(status_counts)


@app.route('/targets/<int:target_id>/note', methods=['POST'])
def update_note_route(target_id):
    """更新站点备注"""
    note = request.form.get('note', '').strip()
    if len(note) > 500:
        note = note[:500]
    update_target_note(target_id, note)

    # 保持当前筛选分页参数
    page = request.form.get('page', '1')
    status = request.form.get('status', 'Vulnerable')
    search = request.form.get('search', '')
    return redirect(url_for('index', page=page, status=status, search=search))


@app.route('/targets/<int:target_id>/archive', methods=['POST'])
def archive_target_route(target_id):
    """归档站点（同 IP 站点一起归档）"""
    target = get_target_by_id(target_id)
    if target and target['ip']:
        update_target_status_by_ip(target['ip'], 'Archived')
    else:
        update_target_status_only(target_id, 'Archived')

    page = request.form.get('page', '1')
    status = request.form.get('status', 'Vulnerable')
    search = request.form.get('search', '')
    return redirect(url_for('index', page=page, status=status, search=search))


@app.route('/targets/<int:target_id>/unarchive', methods=['POST'])
def unarchive_target_route(target_id):
    """取消归档，状态改为待检查"""
    update_target_status_only(target_id, 'Pending')

    page = request.form.get('page', '1')
    status = request.form.get('status', 'Vulnerable')
    search = request.form.get('search', '')
    return redirect(url_for('index', page=page, status=status, search=search))


@app.route('/targets/<int:target_id>/favorite', methods=['POST'])
def favorite_target_route(target_id):
    """更新收藏状态"""
    favorite = request.form.get('favorite', '0') == '1'
    update_target_favorite(target_id, favorite)

    page = request.form.get('page', '1')
    status = request.form.get('status', 'Vulnerable')
    search = request.form.get('search', '')
    return redirect(url_for('index', page=page, status=status, search=search))


@app.route('/explore/<int:target_id>')
def explore(target_id):
    """文件浏览主视图"""
    target = get_target_by_id(target_id)
    if not target:
        return "Target not found", 404

    # 获取当前请求的路径，默认为根目录
    current_path = request.args.get('path', '/')
    base_url = target['base_url']

    # 对文件查看/下载请求直接 302，避免先探测远端内容导致额外等待
    action = request.args.get('action')
    if action in ('view', 'download'):
        target_url = build_remote_url(base_url, current_path)
        return redirect(target_url, code=302)

    data = get_remote_content(base_url, current_path)

    if data['type'] == 'file':
        # 兜底：如果直接访问到文件，也执行 302 跳转
        target_url = build_remote_url(base_url, current_path)
        return redirect(target_url, code=302)

    elif data['type'] == 'directory':
        # 计算面包屑导航
        parts = [p for p in current_path.split('/') if p]
        breadcrumbs = []
        acc = ""
        for p in parts:
            acc += "/" + p
            breadcrumbs.append({'name': p, 'path': acc})

        # 检测 WebDAV 快捷目录
        webdav_shortcuts = []
        
        # 如果在 /share/home 目录，检测子目录
        if current_path.rstrip('/') == '/share/home' or current_path.rstrip('/').startswith('/share/home/'):
            # 获取 home 目录下的所有子目录
            if current_path.rstrip('/') == '/share/home':
                # 当前就在 home 目录，列出所有数字目录
                for item in data['items']:
                    if item['is_dir'] and item['name'].rstrip('/').isdigit():
                        user_id = item['name'].rstrip('/')
                        webdav_path = f"/share/home/{user_id}/webdav"
                        webdav_shortcuts.append({
                            'user_id': user_id,
                            'path': webdav_path
                        })
            else:
                # 在某个用户目录下，检测其他用户目录
                home_data = get_remote_content(base_url, '/share/home')
                if home_data['type'] == 'directory':
                    for item in home_data['items']:
                        if item['is_dir'] and item['name'].rstrip('/').isdigit():
                            user_id = item['name'].rstrip('/')
                            webdav_path = f"/share/home/{user_id}/webdav"
                            webdav_shortcuts.append({
                                'user_id': user_id,
                                'path': webdav_path
                            })

        return render_template('explorer.html',
                               target=target,
                               items=data['items'],
                               current_path=current_path,
                               breadcrumbs=breadcrumbs,
                               target_id=target_id,
                               webdav_shortcuts=webdav_shortcuts)
    else:
        return f"Error: {data.get('msg')}", 500


@app.route('/download_folder/<int:target_id>')
def download_folder_route(target_id):
    """触发递归下载"""
    target = get_target_by_id(target_id)
    path = request.args.get('path', '/')

    zip_stream = recursive_zip_download(target['base_url'], path)

    filename = f"download_{target['ip']}_{path.replace('/', '_')}.zip"
    return send_file(
        zip_stream,
        mimetype='application/zip',
        as_attachment=True,
        download_name=filename
    )


if __name__ == '__main__':
    app.run(debug=True, port=5000)
