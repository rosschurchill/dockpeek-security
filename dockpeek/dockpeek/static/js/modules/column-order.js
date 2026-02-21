import { state } from './state.js';
import { updateFirstAndLastVisibleColumns } from './column-visibility.js';

export function updateFromDOM() {
  const items = document.querySelectorAll('#column-list .draggable');
  state.columnOrder.splice(0, state.columnOrder.length,
    ...Array.from(items).map(item => item.dataset.column));
}

export function reorderMenuItems() {
  const columnList = document.getElementById('column-list');
  const items = Array.from(columnList.children);

  items.sort((a, b) => {
    const aIndex = state.columnOrder.indexOf(a.dataset.column);
    const bIndex = state.columnOrder.indexOf(b.dataset.column);
    return aIndex - bIndex;
  });

  items.forEach(item => columnList.appendChild(item));
}

export function save() {
  localStorage.setItem('columnOrder', JSON.stringify(state.columnOrder));
}

export function load() {
  const saved = localStorage.getItem('columnOrder');
  if (saved) {
    state.columnOrder.splice(0, state.columnOrder.length, ...JSON.parse(saved));
  }
}

export function updateTableOrder() {
  const thead = document.querySelector('#main-table thead tr');
  const headers = Array.from(thead.children);

  state.columnOrder.forEach(columnName => {
    const header = headers.find(h =>
      h.dataset.sortColumn === columnName ||
      h.classList.contains(`${columnName}-column`) ||
      h.classList.contains(`table-cell-${columnName}`)
    );
    if (header) thead.appendChild(header);
  });

  document.querySelectorAll('#container-rows tr').forEach(row => {
    const cells = Array.from(row.children);
    state.columnOrder.forEach(columnName => {
      const cell = cells.find(c =>
        c.classList.contains(`table-cell-${columnName}`) ||
        c.dataset.content === columnName ||
        (columnName === 'server' && c.classList.contains('server-column')) ||
        (columnName === 'traefik' && c.classList.contains('traefik-column'))
      );
      if (cell) row.appendChild(cell);
    });
  });

  updateFirstAndLastVisibleColumns();
}
