import * as ColumnOrder from './column-order.js';

export class DragDropHandler {
  constructor(listId) {
    this.list = document.getElementById(listId);
    this.draggedElement = null;
    this.touchStartY = 0;
    this.isDragging = false;
    this._setupEventListeners();
  }

  _setupEventListeners() {
    this.list.addEventListener('dragstart', this._onDragStart.bind(this));
    this.list.addEventListener('dragend', this._onDragEnd.bind(this));
    this.list.addEventListener('dragover', this._onDragOver.bind(this));
    this.list.addEventListener('drop', this._onDrop.bind(this));
    this.list.addEventListener('touchstart', this._onTouchStart.bind(this), { passive: false });
    this.list.addEventListener('touchmove', this._onTouchMove.bind(this), { passive: false });
    this.list.addEventListener('touchend', this._onTouchEnd.bind(this));

    this.list.querySelectorAll('.draggable').forEach(item => {
      item.draggable = true;
    });
  }

  _onDragStart(e) {
    if (e.target.classList.contains('draggable')) {
      this.draggedElement = e.target;
      e.target.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      e.dataTransfer.setData('text/html', e.target.outerHTML);
    }
  }

  _onDragEnd(e) {
    if (e.target.classList.contains('draggable')) {
      e.target.classList.remove('dragging');
      this.draggedElement = null;
    }
  }

  _onDragOver(e) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';

    const afterElement = this._getDragAfterElement(e.clientY);
    const dragging = this.list.querySelector('.dragging');

    this.list.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));

    if (afterElement == null) {
      this.list.appendChild(dragging);
    } else {
      afterElement.classList.add('drag-over');
      this.list.insertBefore(dragging, afterElement);
    }
  }

  _onDrop(e) {
    e.preventDefault();
    this.list.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));
    this._saveOrder();
  }

  _onTouchStart(e) {
    const target = e.target.closest('.draggable');
    if (target) {
      this.draggedElement = target;
      this.touchStartY = e.touches[0].clientY;
      this.isDragging = false;

      setTimeout(() => {
        if (this.draggedElement) {
          this.isDragging = true;
          this.draggedElement.classList.add('dragging');
        }
      }, 150);
    }
  }

  _onTouchMove(e) {
    if (!this.draggedElement || !this.isDragging) return;

    e.preventDefault();
    const touchY = e.touches[0].clientY;
    const afterElement = this._getDragAfterElement(touchY);

    this.list.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));

    if (afterElement == null) {
      this.list.appendChild(this.draggedElement);
    } else {
      afterElement.classList.add('drag-over');
      this.list.insertBefore(this.draggedElement, afterElement);
    }
  }

  _onTouchEnd(e) {
    if (this.draggedElement) {
      this.list.querySelectorAll('.drag-over').forEach(el => el.classList.remove('drag-over'));

      if (this.isDragging) {
        this.draggedElement.classList.remove('dragging');
        this._saveOrder();
      }

      this.draggedElement = null;
      this.isDragging = false;
    }
  }

  _getDragAfterElement(y) {
    const draggableElements = [...this.list.querySelectorAll('.draggable:not(.dragging)')];

    return draggableElements.reduce((closest, child) => {
      const box = child.getBoundingClientRect();
      const offset = y - box.top - box.height / 2;

      if (offset < 0 && offset > closest.offset) {
        return { offset, element: child };
      }
      return closest;
    }, { offset: Number.NEGATIVE_INFINITY }).element;
  }

  _saveOrder() {
    ColumnOrder.updateFromDOM();
    ColumnOrder.save();
    ColumnOrder.updateTableOrder();
  }
}
