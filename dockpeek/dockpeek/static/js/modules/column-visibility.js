import { state } from './state.js';
import { COLUMN_MAPPINGS } from './constants.js';

export function updateColumnVisibility() {
  for (const [columnName, mapping] of Object.entries(COLUMN_MAPPINGS)) {
    const isVisible = state.columnVisibility[columnName];

    document.querySelectorAll(mapping.selector).forEach(el => {
      el.classList.toggle('column-hidden', !isVisible);
    });

    document.querySelectorAll(`.${mapping.cellClass}`).forEach(el => {
      el.classList.toggle('column-hidden', !isVisible);
    });
  }

  const hasTags = state.filteredAndSortedContainers.some(c => c.tags?.length);
  document.querySelectorAll('.tags-column, .table-cell-tags').forEach(el => {
    el.classList.toggle('column-hidden', !state.columnVisibility.tags || !hasTags);
  });

  updateFirstAndLastVisibleColumns();
}

export function updateFirstAndLastVisibleColumns() {
  const table = document.querySelector('#main-table');
  const rows = Array.from(table.querySelectorAll('tr'));

  rows.forEach(row => {
    row.querySelectorAll('th, td').forEach(cell => {
      cell.classList.remove('first-visible', 'last-visible');
    });
  });

  if (!rows.length) return;

  const columnsCount = rows[0].children.length;
  let firstIndex = -1;
  let lastIndex = -1;

  for (let i = 0; i < columnsCount; i++) {
    const cell = rows[0].children[i];
    if (cell.offsetParent !== null) {
      if (firstIndex === -1) firstIndex = i;
      lastIndex = i;
    }
  }

  rows.forEach(row => {
    if (firstIndex !== -1) row.children[firstIndex].classList.add('first-visible');
    if (lastIndex !== -1) row.children[lastIndex].classList.add('last-visible');
  });
}
