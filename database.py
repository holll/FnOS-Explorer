import sqlite3

DB_PATH = 'vuln_targets.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # 创建 targets 表：存储扫描结果
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            base_url TEXT UNIQUE,  -- 例如 https://1.1.1.1:8080
            host TEXT,             -- 域名或 IP
            ip TEXT,
            port TEXT,
            protocol TEXT,         -- http 或 https
            country TEXT,          -- 国家代码，如 CN, US
            region TEXT,           -- 省份/州，如 广东省, California
            city TEXT,             -- 城市，如 Dongguan, Brea
            status TEXT,           -- 'Vulnerable', 'Safe', 'Pending', 'Error', 'Archived'
            root_content TEXT,     -- 根目录的 HTML 响应快照
            note TEXT DEFAULT '',  -- 备注
            favorite INTEGER DEFAULT 0  -- 是否收藏：0否/1是
        )
    ''')

    # 兼容旧库：补充 note/favorite 字段
    cursor.execute("PRAGMA table_info(targets)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'note' not in columns:
        cursor.execute("ALTER TABLE targets ADD COLUMN note TEXT DEFAULT ''")
    if 'favorite' not in columns:
        cursor.execute("ALTER TABLE targets ADD COLUMN favorite INTEGER DEFAULT 0")
    conn.commit()
    conn.close()

def add_target(base_url, host, ip, port, protocol, country, region, city, status, root_content):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT OR REPLACE INTO targets (base_url, host, ip, port, protocol, country, region, city, status, root_content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (base_url, host, ip, port, protocol, country, region, city, status, root_content))
        conn.commit()
    except Exception as e:
        print(f"DB Error: {e}")
    finally:
        conn.close()

def add_target_batch(targets_list):
    """批量添加目标，去重（已存在的记录保持原状态）"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        # 使用 INSERT OR IGNORE 会跳过已存在的记录，保持原状态
        cursor.executemany('''
            INSERT OR IGNORE INTO targets (base_url, host, ip, port, protocol, country, region, city, status, root_content)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', targets_list)
        conn.commit()
        return cursor.rowcount
    except Exception as e:
        print(f"DB Batch Error: {e}")
        return 0
    finally:
        conn.close()

def get_pending_targets():
    """获取所有待检查的目标"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE status = 'Pending'")
    rows = cursor.fetchall()
    conn.close()
    return rows

def update_target_status(target_id, status, root_content):
    """更新目标状态"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE targets SET status = ?, root_content = ? WHERE id = ?
        ''', (status, root_content, target_id))
        conn.commit()
    except Exception as e:
        print(f"DB Update Error: {e}")
    finally:
        conn.close()


def update_target_status_only(target_id, status):
    """仅更新目标状态"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE targets SET status = ? WHERE id = ?
        ''', (status, target_id))
        conn.commit()
    except Exception as e:
        print(f"DB Update Status Error: {e}")
    finally:
        conn.close()


def update_target_note(target_id, note):
    """更新目标备注"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            UPDATE targets SET note = ? WHERE id = ?
        ''', (note, target_id))
        conn.commit()
    except Exception as e:
        print(f"DB Update Note Error: {e}")
    finally:
        conn.close()


def update_target_favorite(target_id, favorite):
    """更新目标收藏状态"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE targets SET favorite = ? WHERE id = ?", (1 if favorite else 0, target_id))
        conn.commit()
    except Exception as e:
        print(f"DB Update Favorite Error: {e}")
    finally:
        conn.close()

def get_all_targets():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def get_targets_paginated(page=1, per_page=50, status_filter=None, search_query=None):
    """分页获取目标，支持筛选和搜索"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 构建查询条件
    conditions = []
    params = []
    
    if status_filter and status_filter != 'all':
        if status_filter == 'Favorite':
            conditions.append("favorite = 1")
        else:
            conditions.append("status = ?")
            params.append(status_filter)
    
    if search_query:
        conditions.append("(ip LIKE ? OR host LIKE ? OR base_url LIKE ? OR city LIKE ?)")
        params.extend([f"%{search_query}%", f"%{search_query}%", f"%{search_query}%", f"%{search_query}%"])
    
    where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
    
    # 获取总数
    count_query = f"SELECT COUNT(*) as total FROM targets{where_clause}"
    cursor.execute(count_query, params)
    total = cursor.fetchone()['total']
    
    # 获取分页数据
    offset = (page - 1) * per_page
    data_query = f"SELECT * FROM targets{where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
    cursor.execute(data_query, params + [per_page, offset])
    rows = cursor.fetchall()
    
    conn.close()
    
    return {
        'items': rows,
        'total': total,
        'page': page,
        'per_page': per_page,
        'total_pages': (total + per_page - 1) // per_page
    }

def get_status_counts():
    """获取各状态的数量统计"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT status, COUNT(*) as count 
        FROM targets 
        GROUP BY status
    """)
    rows = cursor.fetchall()

    counts = {'all': 0, 'favorite': 0}
    for row in rows:
        counts[row[0]] = row[1]
        counts['all'] += row[1]

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM targets WHERE favorite = 1")
    counts['favorite'] = cursor.fetchone()[0]

    conn.close()
    return counts

def get_target_by_id(tid):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM targets WHERE id = ?", (tid,))
    row = cursor.fetchone()
    conn.close()
    return row