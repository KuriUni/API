(() => {
  'use strict';

  const form = document.getElementById('reception-bulk-form');
  if (!form) return;

  const selectPage = document.getElementById('intake-select-page');
  const count = document.getElementById('intake-selection-count');
  const selections = Array.from(document.querySelectorAll('.intake-select'));
  const dueDate = form.elements.namedItem('bulk_due_at');
  const clearDue = form.elements.namedItem('clear_due_at');

  const refreshSelection = () => {
    const selected = selections.filter((checkbox) => checkbox.checked).length;
    if (count) count.textContent = `${selected}件選択中`;
    if (selectPage) {
      selectPage.checked = selections.length > 0 && selected === selections.length;
      selectPage.indeterminate = selected > 0 && selected < selections.length;
    }
  };

  if (selectPage) {
    selectPage.addEventListener('change', () => {
      selections.forEach((checkbox) => { checkbox.checked = selectPage.checked; });
      refreshSelection();
    });
  }
  selections.forEach((checkbox) => checkbox.addEventListener('change', refreshSelection));

  if (dueDate && clearDue) {
    dueDate.addEventListener('input', () => { if (dueDate.value) clearDue.checked = false; });
    clearDue.addEventListener('change', () => { if (clearDue.checked) dueDate.value = ''; });
  }

  form.addEventListener('submit', (event) => {
    if (!selections.some((checkbox) => checkbox.checked)) {
      event.preventDefault();
      window.alert('更新する受付を選択してください。');
      return;
    }
    const hasChange = ['bulk_status', 'bulk_priority', 'bulk_assigned_admin_id']
      .some((name) => form.elements.namedItem(name)?.value !== '')
      || Boolean(dueDate?.value)
      || Boolean(clearDue?.checked);
    if (!hasChange) {
      event.preventDefault();
      window.alert('変更する項目を1つ以上選んでください。');
    }
  });

  refreshSelection();
})();
