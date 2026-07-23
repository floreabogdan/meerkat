(function () {
	// ---- relative time ----
	// Elements carrying data-ts (RFC3339) get their text swapped to a relative
	// form ("2m ago") and kept fresh; the absolute time stays available in the
	// title tooltip set by the template.
	function relTime(iso) {
		var d = new Date(iso);
		if (isNaN(d.getTime())) return "";
		var s = Math.floor((Date.now() - d.getTime()) / 1000);
		if (s < 0) s = 0;
		if (s < 10) return "just now";
		if (s < 60) return s + "s ago";
		if (s < 3600) return Math.floor(s / 60) + "m ago";
		if (s < 86400) {
			var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
			return m ? h + "h " + m + "m ago" : h + "h ago";
		}
		return Math.floor(s / 86400) + "d ago";
	}
	function refreshTimes() {
		document.querySelectorAll("[data-ts]").forEach(function (el) {
			var iso = el.getAttribute("data-ts");
			if (iso) el.textContent = relTime(iso);
		});
	}
	window.meerkatRelTime = relTime;
	window.meerkatRefreshTimes = refreshTimes;
	refreshTimes();
	setInterval(refreshTimes, 30000);

	// ---- page filter ----
	// Filters any element marked data-search-target by its rows' text content.
	var input = document.getElementById("topbar-search-input");
	if (input && !document.querySelector("[data-search-target]")) {
		// Nothing on this page is filterable — hide the box rather than leave a
		// control that does nothing.
		var wrap = input.closest(".topbar-search");
		if (wrap) wrap.style.display = "none";
		input = null;
	}
	if (input) {
		// The filterable rows of a target: a table's body rows, or (for a
		// non-table target) its direct children.
		var rowsOf = function (target) {
			if (target.tagName === "TABLE") {
				var rows = [];
				Array.prototype.forEach.call(target.tBodies, function (tb) {
					Array.prototype.push.apply(rows, tb.rows);
				});
				return rows;
			}
			return Array.prototype.slice.call(target.children);
		};
		var applyFilter = function () {
			var q = input.value.trim().toLowerCase();
			document.querySelectorAll("[data-search-target]").forEach(function (target) {
				rowsOf(target).forEach(function (row) {
					var match = !q || row.textContent.toLowerCase().indexOf(q) !== -1;
					// Toggle a class rather than inline display, so pagination's own
					// .page-hidden class can coexist (a row shows only when neither
					// is set).
					row.classList.toggle("filtered-out", !match);
				});
			});
			// The visible-row set changed, so recompute pages on any paginated table.
			if (window.meerkatReflowPagination) window.meerkatReflowPagination();
		};
		window.meerkatApplyFilter = applyFilter;
		input.addEventListener("input", applyFilter);
		input.addEventListener("keydown", function (e) {
			if (e.key === "Escape") {
				input.value = "";
				applyFilter();
				input.blur();
			}
		});
		document.addEventListener("keydown", function (e) {
			if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
			var t = e.target;
			if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable)) return;
			e.preventDefault();
			input.focus();
		});
	}

	// ---- mobile navigation ----
	var navToggle = document.getElementById("nav-toggle");
	var scrim = document.getElementById("nav-scrim");
	if (navToggle) {
		navToggle.addEventListener("click", function () {
			document.body.classList.toggle("nav-open");
		});
	}
	if (scrim) {
		scrim.addEventListener("click", function () {
			document.body.classList.remove("nav-open");
		});
	}
	document.addEventListener("keydown", function (e) {
		if (e.key === "Escape") document.body.classList.remove("nav-open");
	});

	// ---- ingest dot ----
	// Answers the question an empty console always raises: is nothing happening,
	// or is nothing being read? Those look identical without this.
	var connDot = document.getElementById("ingest-conn");
	var connLabel = document.getElementById("ingest-conn-label");
	function setConn(cls, text) {
		if (connDot) connDot.className = "conn-dot " + cls;
		if (connLabel) connLabel.textContent = text;
	}
	function poll() {
		fetch("/api/status", { credentials: "same-origin" })
			.then(function (r) { return r.ok ? r.json() : null; })
			.then(function (data) {
				if (!data) { setConn("bad", "status unavailable"); return; }
				if (!data.ingestRunning) {
					setConn("bad", "reader stopped");
				} else if (data.lastError) {
					setConn("warn", "ingest: problem");
				} else if (data.stale) {
					setConn("warn", "eve.json quiet");
				} else {
					setConn("ok", "reading eve.json");
				}
			})
			.catch(function () { setConn("bad", "status unavailable"); });
	}
	if (connDot) {
		poll();
		setInterval(poll, 15000);
	}
})();

// Fill the avatar with the logged-in user's initial (it renders a generic user
// icon until this resolves, so it degrades gracefully without JS).
(function () {
	var avatar = document.querySelector("[data-avatar]");
	if (!avatar) return;
	fetch("/api/me", { credentials: "same-origin" })
		.then(function (r) { return r.ok ? r.json() : null; })
		.then(function (data) {
			if (!data || !data.username) return;
			avatar.textContent = data.username.trim().charAt(0).toUpperCase() || "?";
			var summary = avatar.closest("summary");
			if (summary) summary.title = data.username;
		})
		.catch(function () {});
})();

// The profile menu is a bare <details>; close it on an outside click or Escape
// so it doesn't sit open over other controls once dismissed elsewhere.
(function () {
	var menu = document.querySelector("details.profile-menu");
	if (!menu) return;
	document.addEventListener("click", function (event) {
		if (menu.open && !menu.contains(event.target)) menu.open = false;
	});
	document.addEventListener("keydown", function (event) {
		if (event.key === "Escape" && menu.open) {
			menu.open = false;
			var summary = menu.querySelector("summary");
			if (summary) summary.focus();
		}
	});
})();
