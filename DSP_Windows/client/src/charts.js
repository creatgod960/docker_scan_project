/**
 * Chart.js 헬퍼 모듈
 */
import { Chart, ArcElement, DoughnutController, Tooltip, Legend } from 'chart.js';

Chart.register(ArcElement, DoughnutController, Tooltip, Legend);

const SEV_COLORS = {
  CRITICAL: '#dc2626',
  HIGH:     '#ea580c',
  MEDIUM:   '#ca8a04',
  LOW:      '#16a34a',
  UNKNOWN:  '#6b7280',
};

/** results 배열에서 severity 집계 */
export function countSeverity(results) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const v of results) {
    const key = (v.severity || 'UNKNOWN').toUpperCase();
    counts[key in counts ? key : 'UNKNOWN']++;
  }
  return counts;
}

/** 도넛 그래프 생성 또는 업데이트 */
const _instances = {};

export function renderDonut(canvasId, counts, label = '') {
  const labels = Object.keys(counts).filter(k => counts[k] > 0);
  const data   = labels.map(k => counts[k]);
  const colors = labels.map(k => SEV_COLORS[k]);
  const total  = data.reduce((a, b) => a + b, 0);

  if (_instances[canvasId]) {
    _instances[canvasId].destroy();
  }

  const ctx = document.getElementById(canvasId);
  if (!ctx) return;

  _instances[canvasId] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data, backgroundColor: colors, borderWidth: 2, borderColor: '#1e293b' }],
    },
    options: {
      cutout: '68%',
      plugins: {
        legend: { position: 'right', labels: { color: '#cbd5e1', font: { size: 13 } } },
        tooltip: {
          callbacks: {
            label: c => ` ${c.label}: ${c.raw}건 (${Math.round(c.raw / total * 100)}%)`,
          },
        },
      },
    },
    plugins: [{
      // 가운데 총 개수 표시
      id: 'centerText',
      afterDraw(chart) {
        const { ctx: c, chartArea: { left, right, top, bottom } } = chart;
        const cx = (left + right) / 2;
        const cy = (top + bottom) / 2;
        c.save();
        c.textAlign = 'center';
        c.textBaseline = 'middle';
        c.fillStyle = '#f8fafc';
        c.font = 'bold 28px sans-serif';
        c.fillText(total, cx, cy - 10);
        c.font = '13px sans-serif';
        c.fillStyle = '#94a3b8';
        c.fillText(label || '취약점', cx, cy + 16);
        c.restore();
      },
    }],
  });
}
