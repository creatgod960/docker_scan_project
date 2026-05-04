import subprocess
import sys
import json
import datetime

# [필수 라이브러리]
REQUIRED_PACKAGES = ["dash", "dash-mantine-components", "dash-iconify", "pandas", "plotly", "requests"]

def install_and_import():
    for package in REQUIRED_PACKAGES:
        try:
            import_name = package.replace("-", "_")
            __import__(import_name)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

install_and_import()

import dash
from dash import dcc, html, Input, Output, State, callback, ALL, no_update, ctx, clientside_callback
import dash_mantine_components as dmc
from dash_iconify import DashIconify
import plotly.express as px
import pandas as pd
import requests # API 통신용

app = dash.Dash(__name__, suppress_callback_exceptions=True)

# [명세서 반영 데이터 구조] - 필터링 테이블(PDF)의 항목들을 반영 ㅇㅇㅇ
# 실제 환경에서는 API를 통해 DB에서 이 데이터를 가져오게 됩니다.
MOCK_ANALYSIS_RESULT = {
    "Critical": [
        {"id": "CVE-2024-56433", "type": "Grype(OS)", "pkg": "glibc", "path": "/lib/x86_64-linux-gnu", "installed": "2.31", "fixed": "2.31-13+deb11u11", "desc": "Glibc에서 발생하는 오버플로우 취약점입니다."},
        {"id": "CVE-2023-4567", "type": "Trivy(Lib)", "pkg": "body-parser", "path": "/usr/src/app/node_modules/body-parser", "installed": "1.19.0", "fixed": "1.20.1", "desc": "보안되지 않은 입력을 처리할 때 발생하는 취약점입니다."}
    ],
    "Medium": [
        {"id": "SECRET-01", "type": "Trivy(Secret)", "pkg": "id_rsa", "path": "/root/.ssh/id_rsa", "installed": "N/A", "fixed": "Remove File", "desc": "프라이빗 키 파일이 이미지 레이어에 포함되어 유출되었습니다."}
    ],
    "Normal": [], "Low": [], "Unknown": []
}

COLOR_MAP = {"Critical": "#fa5252", "Medium": "#fd7e14", "Normal": "#40c057", "Low": "#228be6", "Unknown": "#868e96"}

# [UI 컴포넌트]
def create_header():
    return dmc.Group(
        justify="space-between", mb="lg",
        children=[
            dmc.Group([
                DashIconify(icon="tabler:shield-check", width=35, color="#228be6"),
                dmc.Title("Project WH: Vulnerability Dashboard", order=2)
            ]),
            dmc.Group([
                # 3. PDF 저장 버튼 (브라우저 인쇄 기능 활용)
                dmc.Button(
                    "PDF로 저장", id="btn-pdf", variant="outline", leftSection=DashIconify(icon="tabler:file-download"),
                    color="gray"
                ),
                dmc.Switch(
                    id="theme-switch", size="lg",
                    onLabel=DashIconify(icon="tabler:moon-stars", width=16, color="yellow"),
                    offLabel=DashIconify(icon="tabler:sun", width=16, color="orange")
                )
            ])
        ]
    )

# [레이아웃 구성]
app.layout = dmc.MantineProvider(
    id="mantine-provider", forceColorScheme="light",
    children=[
        dcc.Store(id='upload-log-store', data=[]),
        html.Div(
            id="print-area", # PDF 저장 시 캡처될 영역
            style={"minHeight": "100vh", "padding": "20px 0"},
            children=[
                dmc.Container(
                    size="xl",
                    children=[
                        create_header(),
                        # 업로드 섹션
                        dmc.Paper(
                            withBorder=True, shadow="sm", radius="md", p="md", mb="xl",
                            children=[
                                dmc.Text("분석 파일 업로드 (image.tar)", fw=700, mb="md"),
                                dcc.Upload(
                                    id='upload-data', multiple=False,
                                    children=html.Div([
                                        DashIconify(icon="tabler:upload", width=30),
                                        dmc.Text("파일을 드래그하거나 클릭하세요.")
                                    ]),
                                    style={
                                        'width': '100%', 'height': '80px', 'borderWidth': '2px',
                                        'borderStyle': 'dashed', 'borderColor': '#ced4da', 'borderRadius': '8px',
                                        'display': 'flex', 'alignItems': 'center', 'justifyContent': 'center', 'cursor': 'pointer'
                                    }
                                )
                            ]
                        ),
                        dmc.Grid(
                            gutter="lg",
                            children=[
                                dmc.GridCol(id="sec-1", span=6), # 섹션 1: 그래프
                                dmc.GridCol(id="sec-2", span=6), # 섹션 2: 필터링 리스트
                                dmc.GridCol(id="sec-3", span=6), # 섹션 3: 라이선스/SBOM 통계 (제안)
                                dmc.GridCol(id="sec-4", span=6,
                                    children=dmc.Paper(
                                        withBorder=True, p="md", radius="md", style={"height":"350px", "overflowY":"auto"},
                                        children=[
                                            dmc.Text("섹션 4: 분석 로그", fw=700, mb="sm"),
                                            dmc.Text("업로드된 파일이 없습니다.", c="dimmed", ta="center", mt=50)
                                        ]
                                    )
                                ), # 섹션 4: 로그
                            ]
                        )
                    ]
                ),
                dmc.Modal(
                    id="detail-modal", title=dmc.Text("취약점 상세 정보 (Filtered Data)", fw=700),
                    centered=True, size="lg", overlayProps={"backgroundOpacity": 0.5, "blur": 3},
                    children=[html.Div(id="modal-content")]
                )
            ]
        )
    ]
)

# [콜백 함수들]

# 1. 파일 업로드 -> API 전송 (Mock) 및 로그
@callback(
    Output("upload-log-store", "data"),
    Output("sec-4", "children"),
    Input("upload-data", "contents"),
    State("upload-data", "filename"),
    State("upload-log-store", "data"),
    prevent_initial_call=True
)
def handle_upload(contents, filename, current_logs):
    # API 전송 로직 (예시)
    # response = requests.post("http://your-api-url/analyze", files={"file": contents})
    
    now_str = datetime.datetime.now().strftime("%H:%M:%S")
    log_entry = {
        "time": now_str, 
        "content": f"파일이 서버로 전송되었습니다.\n(분석 모듈 API 호출 시작: {filename})"
    }
    current_logs = [log_entry] + (current_logs or [])
    
    rows = [html.Tr([html.Td(l["time"]), html.Td(l["content"], style={"whiteSpace": "pre-wrap"})]) for l in current_logs]
    table = dmc.Paper(withBorder=True, p="md", radius="md", style={"height":"350px", "overflowY":"auto"}, children=[
        dmc.Text("섹션 4: 분석 로그", fw=700, mb="sm"),
        dmc.Table(striped=True, children=[html.Tbody(rows)])
    ])
    return current_logs, table

# 2. 섹션 1 & 2: 가공된 데이터 기반 출력
@callback(
    Output("sec-1", "children"),
    Output("sec-2", "children"),
    Input("upload-log-store", "data") # 업로드가 완료되면 데이터를 불러오는 것으로 가정
)
def update_dashboard(log_data):
    # 파이 차트 생성 (Section 1)
    df = pd.DataFrame([{"Cat": k, "Count": len(v)} for k, v in MOCK_ANALYSIS_RESULT.items()])
    fig = px.pie(df, names='Cat', values='Count', color='Cat', color_discrete_map=COLOR_MAP, hole=0.6)
    fig.update_traces(textinfo='none', hovertemplate='%{label}: %{value}<extra></extra>')
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), showlegend=True, paper_bgcolor='rgba(0,0,0,0)')
    
    sec1 = dmc.Paper(withBorder=True, p="xl", radius="md", style={"height":"350px"}, children=[
        dmc.Text("섹션 1: 위험도별 분포", fw=700, mb="sm"),
        dcc.Graph(id="vuln-pie-chart", figure=fig, style={"height":"250px"}, config={'displaylogo': False})
    ])
    
    # 리스트 테이블 생성 (Section 2)
    sec2 = dmc.Paper(withBorder=True, p="xl", radius="md", style={"height":"350px", "overflowY":"auto"}, children=[
        dmc.Text("섹션 2: 취약점 필터링 결과", fw=700, mb="sm"),
        html.Div(id="section-2-content", children=dmc.Text("그래프를 클릭하여 상세 내용을 확인하세요.", c="dimmed", ta="center", mt=50))
    ])
    
    return sec1, sec2

# 섹션 2 리스트 업데이트 및 모달
@callback(
    Output("section-2-content", "children"),
    Input("vuln-pie-chart", "clickData"),
    prevent_initial_call=True
)
def show_specific_list(clickData):
    cat = clickData['points'][0]['label']
    items = MOCK_ANALYSIS_RESULT.get(cat, [])
    rows = [
        html.Tr(
            id={"type": "list-item", "index": item["id"], "cat": cat},
            style={"cursor": "pointer"},
            children=[html.Td(item["id"], style={"color":"#868e96"}), html.Td(f"{item['type']} - {item['pkg']}")]
        ) for item in items
    ]
    return dmc.Table(highlightOnHover=True, striped=True, children=[
        html.Thead(html.Tr([html.Th("ID (CVE)"), html.Th("분류 및 패키지")])),
        html.Tbody(rows)
    ])

@callback(
    Output("detail-modal", "opened"),
    Output("modal-content", "children"),
    Input({"type": "list-item", "index": ALL, "cat": ALL}, "n_clicks"),
    prevent_initial_call=True
)
def open_modal(n_clicks):
    if not any(n_clicks): return no_update
    tid = ctx.triggered_id
    item = next(i for i in MOCK_ANALYSIS_RESULT[tid['cat']] if i['id'] == tid['index'])
    
    return True, dmc.Stack([
        dmc.Group([dmc.Badge(tid['cat'], color=COLOR_MAP[tid['cat']].replace('#','')), dmc.Text(item['id'], fw=700)]),
        dmc.Grid([
            dmc.GridCol(dmc.Text("패키지명", fw=600), span=4), dmc.GridCol(dmc.Text(item['pkg']), span=8),
            dmc.GridCol(dmc.Text("설치 경로", fw=600), span=4), dmc.GridCol(dmc.Text(item['path'], size="xs"), span=8),
            dmc.GridCol(dmc.Text("현재 버전", fw=600), span=4), dmc.GridCol(dmc.Text(item['installed']), span=8),
            dmc.GridCol(dmc.Text("해결 버전", fw=600), span=4), dmc.GridCol(dmc.Text(item['fixed'], c="blue", fw=700), span=8),
        ]),
        dmc.Divider(),
        dmc.Text("상세 설명", fw=600),
        dmc.Text(item['desc'], size="sm")
    ])

# 3. PDF 저장 (브라우저 프린트 팝업 호출)
clientside_callback(
    """
    function(n_clicks) {
        if(n_clicks > 0) {
            window.print();
        }
        return null;
    }
    """,
    Output("btn-pdf", "n_clicks_clear"), # 더미 출력
    Input("btn-pdf", "n_clicks"),
    prevent_initial_call=True
)

# 테마 스위치
@callback(Output("mantine-provider", "forceColorScheme"), Input("theme-switch", "checked"))
def toggle_theme(checked): return "dark" if checked else "light"

# 4. 섹션 3 제안 내용 구성
@callback(Output("sec-3", "children"), Input("mantine-provider", "id"))
def create_sec_3(_):
    # SBOM의 '라이선스' 정보를 시각화하는 바 차트 제안
    license_data = pd.DataFrame({"License": ["MIT", "GPL-2.0", "Apache-2.0", "Unknown"], "Count": [15, 5, 8, 2]})
    fig = px.bar(license_data, x='License', y='Count', color='License', text_auto=True)
    fig.update_layout(margin=dict(l=10, r=10, t=10, b=10), showlegend=False, height=250, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
    
    return dmc.Paper(withBorder=True, p="xl", radius="md", style={"height":"350px"}, children=[
        dmc.Text("섹션 3: 라이선스 준수 현황 (SBOM 통계)", fw=700, mb="sm"),
        dmc.Text("이미지에 포함된 패키지의 라이선스 분포입니다.", size="xs", c="dimmed", mb="md"),
        dcc.Graph(figure=fig, config={'displaylogo': False})
    ])

if __name__ == "__main__":
    app.run(debug=True)
