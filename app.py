import dash
from dash import dcc, html, Input, Output, State, ALL, ctx, no_update
import dash_bootstrap_components as dbc
import json
import os
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
import logging
import hashlib
from functools import wraps

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
DB_FILE = "network_inventory.json"
HISTORY_FILE = "power_history.json"
ALERTS_FILE = "alerts_history.json"
USERS_FILE = "users.json"
SESSION_TIMEOUT = 3600  # 1 hour

# ==================== نظام المصادقة ====================

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return {"users": []}
    else:
        default_users = {
            "users": [
                {
                    "username": "admin",
                    "password": "admin",
                    "role": "full",
                    "first_login": True,
                    "created_at": datetime.now().isoformat()
                }
            ]
        }
        save_users(default_users)
        return default_users

def save_users(users_data):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users_data, f, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def authenticate_user(username, password):
    users_data = load_users()
    for user in users_data.get("users", []):
        if user["username"] == username:
            if len(user["password"]) == 64: 
                if verify_password(password, user["password"]):
                    return user
            else:
                if user["password"] == password:
                    return user
    return None

def update_password(username, new_password):
    users_data = load_users()
    for user in users_data.get("users", []):
        if user["username"] == username:
            user["password"] = hash_password(new_password)
            user["first_login"] = False
            save_users(users_data)
            return True
    return False

def add_user(username, password, role, created_by):
    users_data = load_users()
    for user in users_data.get("users", []):
        if user["username"] == username:
            return False, "User already exists"
    users_data["users"].append({
        "username": username,
        "password": hash_password(password),
        "role": role,
        "first_login": False,
        "created_by": created_by,
        "created_at": datetime.now().isoformat()
    })
    save_users(users_data)
    return True, "User added successfully"

def delete_user(username, current_user):
    if username == current_user:
        return False, "Cannot delete yourself"
    if username == "admin":
        return False, "Cannot delete admin user"
    users_data = load_users()
    users_data["users"] = [u for u in users_data["users"] if u["username"] != username]
    save_users(users_data)
    return True, "User deleted successfully"

# ==================== دوال JSON ====================

def load_json(file):
    if os.path.exists(file):
        try:
            with open(file, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Corrupted JSON file: {file}")
            return {}
    return {}

def save_json(data, file):
    try:
        if os.path.exists(file):
            backup_file = f"{file}.backup"
            try:
                with open(file, 'r', encoding='utf-8') as src:
                    with open(backup_file, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
            except: pass
        with open(file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Error saving {file}: {e}")
        return False

# ==================== صفحات المصادقة ====================

def get_login_layout():
    return dbc.Container([
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.H1("🔐 HRiNS Fiber Monitor", className="text-center text-info mb-4"),
                    html.H4("Login", className="text-center mb-4"),
                    dbc.Input(id="login-username", placeholder="Username", type="text", className="mb-3"),
                    dbc.Input(id="login-password", placeholder="Password", type="password", className="mb-3"),
                    dbc.Button("Login", id="login-button", color="primary", className="w-100 mb-3"),
                    html.Div(id="login-message", className="text-danger text-center")
                ], style={"maxWidth": "400px", "margin": "100px auto", "padding": "30px", "borderRadius": "10px", "backgroundColor": "#222", "boxShadow": "0 0 20px rgba(0,0,0,0.5)"})
            ])
        ])
    ], fluid=True, style={"height": "100vh", "backgroundColor": "#111"})

def get_change_password_layout(username):
    return dbc.Container([
        dbc.Row([
            dbc.Col([
                html.Div([
                    html.H1("🔐 HRiNS Fiber Monitor", className="text-center text-info mb-4"),
                    html.H4(f"Welcome {username}! Please change your password", className="text-center mb-4"),
                    dbc.Input(id="change-old-password", placeholder="Current Password", type="password", className="mb-3"),
                    dbc.Input(id="change-new-password", placeholder="New Password", type="password", className="mb-3"),
                    dbc.Input(id="change-confirm-password", placeholder="Confirm New Password", type="password", className="mb-3"),
                    dbc.Button("Change Password", id="change-password-button", color="success", className="w-100 mb-3"),
                    html.Div(id="change-message", className="text-danger text-center")
                ], style={"maxWidth": "400px", "margin": "100px auto", "padding": "30px", "borderRadius": "10px", "backgroundColor": "#222", "boxShadow": "0 0 20px rgba(0,0,0,0.5)"})
            ])
        ])
    ], fluid=True, style={"height": "100vh", "backgroundColor": "#111"})

def get_user_management_layout(current_user):
    users_data = load_users()
    user_items = []
    for user in users_data.get("users", []):
        if user["username"] != "admin":
            delete_btn = dbc.Button("Delete", id={'type': 'delete-user', 'index': user['username']}, color="danger", size="sm", disabled=(user['username'] == current_user))
            user_items.append(dbc.ListGroupItem([html.Div([html.Span(f"{user['username']} - {user['role']} "), html.Small(f"(Created: {user.get('created_at', 'Unknown')[:10]})", className="text-muted me-3"), delete_btn], className="d-flex justify-content-between align-items-center")]))
    return dbc.Container([dbc.Row([dbc.Col([html.Div([dbc.Row([dbc.Col(html.H2("👥 User Management", className="text-info"), width=8), dbc.Col(dbc.Button("← Back", href="/dashboard", color="secondary", className="float-end"), width=4)]), html.Hr(), dbc.Card([dbc.CardHeader("Add New User"), dbc.CardBody([dbc.Row([dbc.Col([dbc.Input(id="new-user-username", placeholder="Username", type="text", className="mb-2")], width=4), dbc.Col([dbc.Input(id="new-user-password", placeholder="Password", type="password", className="mb-2")], width=4), dbc.Col([dbc.Select(id="new-user-role", options=[{"label": "Full Access", "value": "full"}, {"label": "Read Only", "value": "readonly"}], value="readonly", className="mb-2")], width=2), dbc.Col([dbc.Button("Add User", id="add-user-btn", color="success", className="w-100")], width=2)])])], className="mb-4"), html.H4("Existing Users", className="mb-3"), dbc.ListGroup(user_items, flush=True), html.Div(id="user-management-message", className="mt-3")], style={"padding": "20px"})], width=10)], justify="center")], fluid=True)

# ==================== الصفحة الرئيسية ====================

def get_dashboard_layout(session):
    return html.Div([
        dcc.Interval(id='ui-refresh', interval=10*1000, n_intervals=0),
        dcc.Interval(id='alerts-refresh', interval=30*1000, n_intervals=0),
        dcc.Store(id='active-item-store', storage_type='session'),
        dbc.Container([
            dbc.Row([
                dbc.Col([
                    html.Div([
                        dbc.Row([
                            dbc.Col(html.H4(f"Welcome, {session['username']}", style={"color": "orange"}, className="mt-2"), width=6),
                            dbc.Col([
                                html.Div([
                                    dbc.Button("👥 Users", href="/users", color="warning", size="sm", className="me-2") if session['role'] == 'full' else None,
                                    dbc.Button("🚪 Logout", id="logout-btn", color="danger", size="sm", href="/login")
                                ], className="float-end mt-2")
                            ], width=6)
                        ]),
                        html.Hr(style={"borderColor": "orange"})
                    ])
                ])
            ]),
            dbc.Row([
                dbc.Col([
                    html.Div([
                        # العنوان مع الدائرة البرتقالية والكتابة البرتقالية
                        html.H4([
                            html.Span(style={
                                "height": "12px",
                                "width": "12px",
                                "backgroundColor": "orange",
                                "borderRadius": "50%",
                                "display": "inline-block",
                                "marginRight": "10px",
                                "verticalAlign": "middle"
                            }),
                            html.Span("HRiNS Fiber Monitor", style={"color": "orange", "verticalAlign": "middle"})
                        ], className="mt-3"),
                        
                        dbc.Button("➕ Add Device", id="open-add-dev", color="warning", outline=True, size="sm", className="w-100 mb-2", disabled=session['role'] == 'readonly'),
                        
                        html.Div([
                            html.I(className="fas fa-bell me-2", style={"color": "orange"}),
                            html.Span("Active Alerts", id="alerts-badge", className="badge bg-danger ms-2")
                        ], className="mt-2 mb-2"),
                        
                        html.Hr(style={"borderColor": "orange"}),
                        html.Div(id="sidebar-tree", style={"overflowY": "auto", "height": "70vh"})
                    ], style={"borderRight": "1px solid #444"})
                ], width=3),
                
                dbc.Col([
                    dbc.Row([
                        dbc.Col(html.Div(id="header-title"), width=8),
                        dbc.Col(
                            dbc.ButtonGroup([
                                dbc.Button("2 Days", id="btn-2d", color="warning", outline=True, size="sm"),
                                dbc.Button("7 Days", id="btn-7d", color="warning", outline=True, size="sm"),
                                dbc.Button("30 Days", id="btn-30d", color="warning", outline=True, size="sm")
                            ], className="float-end mt-3"), 
                            width=4
                        )
                    ]),
                    html.Div(id="main-content")
                ], width=9)
            ]),
            
            # Modals تبقى كما هي لكن يمكن تغيير لون الأزرار لمتناسق
            dbc.Modal([
                dbc.ModalHeader("Add New Device"),
                dbc.ModalBody([
                    dbc.Input(id="new-name", placeholder="Device Name", className="mb-2"),
                    dbc.Input(id="new-ip", placeholder="IP Address", className="mb-2"),
                    dbc.Input(id="new-comm", placeholder="SNMP Community", className="mb-2"),
                    dbc.Select(id="new-type", options=[
                        {"label":"Cisco IOS-XE","value":"cisco_iosxe"},
                        {"label":"Cisco NX-OS","value":"cisco_nxos"},
                        {"label":"Arista EOS","value":"arista_eos"}
                    ], value="cisco_iosxe", className="mb-2"),
                    dbc.Label("Alert Thresholds:"),
                    dbc.Input(id="new-threshold-warn", type="number", placeholder="Warning Th", value=-16, className="mb-2"),
                    dbc.Input(id="new-threshold-critical", type="number", placeholder="Critical Th", value=-20, className="mb-2")
                ]),
                dbc.ModalFooter(dbc.Button("Save", id="save-btn", color="warning"))
            ], id="modal-add", is_open=False),
            
            dbc.Modal([
                dbc.ModalHeader("⚠️ Alerts History"),
                dbc.ModalBody(id="alerts-modal-body", style={"maxHeight": "500px", "overflowY": "auto"})
            ], id="modal-alerts", size="lg", is_open=False)
        ], fluid=True)
    ])

# ==================== التطبيق ====================

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.CYBORG], suppress_callback_exceptions=True)
app.title = "HRiNS Fiber Monitor"
app.layout = html.Div([dcc.Location(id='url', refresh=False), dcc.Store(id='session-store', storage_type='session'), dcc.Interval(id='session-check', interval=60*1000, n_intervals=0), html.Div(id='page-content')])

# --- Routing Callbacks ---
@app.callback(Output('url', 'pathname'), [Input('url', 'pathname')])
def redirect_root(pathname):
    if pathname == '/' or pathname == '': return '/login'
    return pathname

@app.callback(Output('page-content', 'children'), [Input('url', 'pathname')], [State('session-store', 'data')])
def display_page(pathname, session):
    if pathname not in ['/login', '/change-password']:
        if not session or 'username' not in session: return dcc.Location(pathname='/login', id='rl')
    if pathname == '/login': return get_login_layout()
    elif pathname == '/change-password': return get_change_password_layout(session['username'])
    elif pathname == '/users': return get_user_management_layout(session['username'])
    elif pathname == '/dashboard': return get_dashboard_layout(session)
    return dcc.Location(pathname='/login', id='rl2')

# --- Auth Callbacks ---
@app.callback([Output('url', 'pathname', allow_duplicate=True), Output('session-store', 'data'), Output('login-message', 'children')], [Input('login-button', 'n_clicks')], [State('login-username', 'value'), State('login-password', 'value')], prevent_initial_call=True)
def login_user(n, u, p):
    user = authenticate_user(u, p)
    if user:
        sd = {'username': user['username'], 'role': user['role'], 'first_login': user.get('first_login', False)}
        return ('/change-password' if sd['first_login'] else '/dashboard'), sd, ""
    return no_update, no_update, "Invalid Login"

# ==================== الـ Callback المعدل للحذف ====================

@app.callback(
    [Output("sidebar-tree", "children"), 
     Output("modal-add", "is_open"),
     Output("alerts-badge", "children")],
    [Input("save-btn", "n_clicks"), 
     Input("open-add-dev", "n_clicks"), 
     Input({'type': 'del-port', 'index': ALL}, 'n_clicks'),
     Input({'type': 'del-dev', 'index': ALL}, 'n_clicks'), # <<< إضافة زر حذف الجهاز
     Input({'type': 'mute-port', 'index': ALL}, 'n_clicks'),
     Input({'type': 'add-p-btn', 'index': ALL}, 'n_clicks'),
     Input("alerts-refresh", "n_intervals")],
    [State("new-name", "value"), State("new-ip", "value"), State("new-comm", "value"), State("new-type", "value"), State("new-threshold-warn", "value"), State("new-threshold-critical", "value"), State("modal-add", "is_open"), State({'type': 'p-drop', 'index': ALL}, 'value'), State({'type': 'p-drop', 'index': ALL}, 'id'), State('session-store', 'data')]
)
def update_tree_logic(n_save, n_open, n_del, n_del_dev, n_mute, n_add_port, n_int, name, ip, comm, dtype, warn_th, crit_th, is_open, drop_values, drop_ids, session):
    is_readonly = session and session.get('role') == 'readonly'
    inv = load_json(DB_FILE)
    alerts = load_json(ALERTS_FILE)
    tid = ctx.triggered_id
    active_alerts = len([a for a in alerts.get('active', []) if not a.get('acknowledged')])

    # منطق حذف الجهاز بالكامل (جديد)
    if isinstance(tid, dict) and tid['type'] == 'del-dev' and not is_readonly:
        dn = tid['index']
        if dn in inv:
            device_ip = inv[dn].get('ip', '')
            del inv[dn]
            save_json(inv, DB_FILE)
            hist = load_json(HISTORY_FILE)
            keys_to_del = [k for k in hist.keys() if k.startswith(f"{device_ip}_")]
            for k in keys_to_del: del hist[k]
            save_json(hist, HISTORY_FILE)
            logger.info(f"Deleted device: {dn}")

    # منطق حذف بورت
    if isinstance(tid, dict) and tid['type'] == 'del-port' and not is_readonly:
        dn, pn = tid['index'].split('|')
        if dn in inv:
            inv[dn]['ports'] = [p for p in inv[dn]['ports'] if p['name'] != pn]
            save_json(inv, DB_FILE)

    # منطق كتم التنبيه
    if isinstance(tid, dict) and tid['type'] == 'mute-port' and not is_readonly:
        dn, pn = tid['index'].split('|')
        if dn in inv:
            for p in inv[dn]['ports']:
                if p['name'] == pn: p['ignore_threshold'] = not p.get('ignore_threshold', False)
            save_json(inv, DB_FILE)

    # إضافة بورت
    if isinstance(tid, dict) and tid['type'] == 'add-p-btn' and not is_readonly:
        dn = tid['index']
        selected_port = next((val for val, d_id in zip(drop_values, drop_ids) if d_id.get('index') == dn), None)
        if selected_port and dn in inv:
            if not any(p['name'] == selected_port for p in inv[dn]['ports']):
                desc = inv[dn].get('port_descriptions', {}).get(selected_port, "No Description")
                inv[dn]['ports'].append({"name": selected_port, "description": desc, "ignore_threshold": False, "added_date": datetime.now().isoformat()})
                save_json(inv, DB_FILE)

    # حفظ جهاز جديد
    if tid == "save-btn" and all([name, ip, comm]) and not is_readonly:
        inv[name] = {"ip": ip, "type": dtype, "community": comm, "ports": [], "available_ports": None, "port_descriptions": {}, "thresholds": {"warning": warn_th or -16, "critical": crit_th or -20}}
        save_json(inv, DB_FILE)
        return no_update, False, active_alerts

    # بناء واجهة الشجرة (مع زر الحذف)
    nodes = []
    for dn, di in inv.items():
        port_options = [{'label': f"{p} ({di.get('port_descriptions', {}).get(p, '')})", 'value': p} for p in (di.get('available_ports') or []) if p not in [x['name'] for x in di.get('ports', [])]]
        alert_ports = [a['port_id'].split('|')[1] for a in alerts.get('active', []) if a.get('port_id', '').startswith(f"{dn}|")]
        
        port_list = []
        for p in sorted(di.get('ports', []), key=lambda x: x['name']):
            port_list.append(html.Div([
                html.Div([dbc.Button(f"{p['name']}", id={'type': 'port-link', 'index': f"{dn}|{p['name']}"}, color="link", size="sm", className=f"p-0 {'text-danger' if p['name'] in alert_ports else 'text-info'}"), html.Small(f" - {p.get('description', '')}", className="text-muted d-block", style={"fontSize": "0.7rem"})], style={"flex": "1"}),
                html.Div([dbc.Button("🔔" if not p.get('ignore_threshold') else "🔕", id={'type': 'mute-port', 'index': f"{dn}|{p['name']}"}, color="link", size="sm", className="p-0 me-2", disabled=is_readonly), dbc.Button("❌", id={'type': 'del-port', 'index': f"{dn}|{p['name']}"}, color="link", size="sm", className="text-danger p-0", disabled=is_readonly)], className="d-flex align-items-center")
            ], className="d-flex justify-content-between mb-1 border-bottom border-secondary pb-1"))

        # العنوان الجديد مع زر سلة المهملات
        header = html.Div([
            html.Span(f"🖥️ {dn} {'⚠️' if any(p['name'] in alert_ports for p in di.get('ports', [])) else ''}"),
            dbc.Button("🗑️", id={'type': 'del-dev', 'index': dn}, color="link", size="sm", className="text-danger p-0 ms-2", style={"textDecoration": "none"}, disabled=is_readonly)
        ], className="d-flex justify-content-between align-items-center w-100")

        nodes.append(dbc.Accordion([dbc.AccordionItem([dbc.Row([dbc.Col(dcc.Dropdown(id={'type': 'p-drop', 'index': dn}, options=port_options, placeholder="Port...", className="text-dark sm"), width=9), dbc.Col(dbc.Button("➕", id={'type': 'add-p-btn', 'index': dn}, color="success", size="sm", disabled=is_readonly), width=3)], className="mb-2 g-0"), html.Div(port_list)], title=header, item_id=dn)], flush=True, start_collapsed=True, className="mb-1"))

    return (nodes if nodes else [html.Div("No devices", className="text-muted text-center mt-3")]), (not is_open if tid == "open-add-dev" else False), active_alerts

# --- Analytics Display (دعم الـ Lanes كما في كودك) ---
@app.callback([Output("main-content", "children"), Output("header-title", "children"), Output("active-item-store", "data")], [Input({'type': 'port-link', 'index': ALL}, 'n_clicks'), Input("btn-2d", "n_clicks"), Input("btn-7d", "n_clicks"), Input("btn-30d", "n_clicks"), Input('ui-refresh', 'n_intervals')], [State("active-item-store", "data")])
def display_analytics(n_l, n2, n7, n30, n_int, active_item):
    triggered = ctx.triggered_id
    if isinstance(triggered, dict) and triggered['type'] == 'port-link': active_item = triggered['index']
    if not active_item: return html.Div("Select a port"), "", None
    
    dn, pn = active_item.split('|')
    inv = load_json(DB_FILE)
    hist = load_json(HISTORY_FILE)
    dev_info = inv.get(dn, {})
    pid = f"{dev_info.get('ip')}_{pn}".replace("/", "-")
    data = hist.get(pid, [])
    
    if not data: return html.Div(f"No data for {pid}"), html.H3(f"{dn} - {pn}"), active_item
    
    df = pd.DataFrame(data)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # دعم عرض الـ Lanes
    last_entry = data[-1]
    lanes = last_entry.get('lanes', [])
    lane_cards = [dbc.Col(dbc.Card([dbc.CardHeader(f"Lane {i+1}", className="p-1 small"), dbc.CardBody(html.H5(f"{v}"), className="p-1")], color="success" if v > -16 else "danger", inverse=True)) for i, v in enumerate(lanes)]

    fig = go.Figure(go.Scatter(x=df['timestamp'], y=df['power'], mode='lines+markers', name='Power'))
    fig.update_layout(template="plotly_dark", height=400, margin=dict(l=20, r=20, t=20, b=20))
    
    content = html.Div([dbc.Row(lane_cards, className="mb-3"), dbc.Card(dbc.CardBody(dcc.Graph(figure=fig)))])
    return content, html.H3(f"{dn} - {pn}"), active_item
# أضف هذا الـ Callback في نهاية الملف قبل سطر التشغيل الرئيسي

@app.callback(
    [Output("user-management-message", "children"),
     Output("url", "pathname", allow_duplicate=True)],
    [Input("add-user-btn", "n_clicks"),
     Input({'type': 'delete-user', 'index': ALL}, 'n_clicks')],
    [State("new-user-username", "value"),
     State("new-user-password", "value"),
     State("new-user-role", "value"),
     State('session-store', 'data')],
    prevent_initial_call=True
)
def manage_users_logic(n_add, n_del_list, uname, pword, urole, session):
    # التحقق من الصلاحيات
    if not session or session.get('role') != 'full':
        return dbc.Alert("Unauthorized!", color="danger"), no_update

    tid = ctx.triggered_id

    # منطق إضافة مستخدم جديد
    if tid == "add-user-btn":
        if not uname or not pword:
            return dbc.Alert("Please fill all fields", color="warning"), no_update
        
        success, msg = add_user(uname, pword, urole, session['username'])
        if success:
            # إعادة تحميل الصفحة لتحديث القائمة
            return dbc.Alert(msg, color="success"), "/users"
        else:
            return dbc.Alert(msg, color="danger"), no_update

    # منطق حذف مستخدم
    if isinstance(tid, dict) and tid.get('type') == 'delete-user':
        target_user = tid['index']
        success, msg = delete_user(target_user, session['username'])
        if success:
            # إعادة تحميل الصفحة لتحديث القائمة
            return dbc.Alert(msg, color="success"), "/users"
        else:
            return dbc.Alert(msg, color="danger"), no_update

    return no_update, no_update

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8050, debug=False) # تأكد من وجود host='0.0.0.0'