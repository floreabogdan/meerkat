// Bulk selection on the sources table.
//
// Progressive enhancement: with no JS the checkboxes and the action buttons are
// still a plain form that posts the ticked addresses, so nothing here is load
// bearing. What it adds is the running count, the select-all, and hiding the
// action bar until something is actually selected — a row of destructive
// buttons sitting permanently under the table invites a mis-click.
(function () {
	"use strict";
	var form = document.querySelector("[data-bulk]");
	if (!form) return;

	var all = form.querySelector("[data-bulk-all]");
	var bar = form.querySelector("[data-bulk-bar]");
	var count = form.querySelector("[data-bulk-count]");

	function items() {
		// Only rows the filter and paginator are currently showing: ticking
		// "select all" must never quietly include rows nobody can see.
		return Array.prototype.filter.call(form.querySelectorAll("[data-bulk-item]"), function (box) {
			var row = box.closest("tr");
			return row && !row.classList.contains("filtered-out") && !row.classList.contains("page-hidden");
		});
	}
	function selected() {
		return items().filter(function (b) { return b.checked; });
	}
	function sync() {
		var n = selected().length;
		if (count) count.textContent = String(n);
		if (bar) bar.hidden = n === 0;
		if (all) {
			var total = items().length;
			all.checked = n > 0 && n === total;
			all.indeterminate = n > 0 && n < total;
		}
	}

	if (all) {
		all.addEventListener("change", function () {
			items().forEach(function (b) { b.checked = all.checked; });
			sync();
		});
	}
	form.addEventListener("change", function (e) {
		if (e.target && e.target.hasAttribute && e.target.hasAttribute("data-bulk-item")) sync();
	});

	// A hidden row's checkbox must not travel with the form: the operator
	// filtered it away, so it is not part of what they selected.
	form.addEventListener("submit", function () {
		Array.prototype.forEach.call(form.querySelectorAll("[data-bulk-item]"), function (box) {
			var row = box.closest("tr");
			if (row && (row.classList.contains("filtered-out") || row.classList.contains("page-hidden"))) {
				box.checked = false;
			}
		});
	});

	sync();
})();
