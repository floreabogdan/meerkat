// live.js polls for alerts newer than the cursor the page was rendered with and
// prepends them. Polling rather than a websocket: meerkat serves one operator on
// a router, the update rate is human-scale, and a plain GET survives an SSH
// tunnel, a reverse proxy and a laptop lid closing without any reconnect logic.
(function () {
	"use strict";

	var body = document.getElementById("live-body");
	if (!body) return;

	var status = document.getElementById("live-status");
	var countEl = document.getElementById("live-count");
	var follow = document.getElementById("live-follow");
	var cursor = parseInt(body.getAttribute("data-cursor"), 10) || 0;
	var received = 0;

	// MAX_ROWS bounds the DOM. A flood would otherwise grow the table without
	// limit and eventually hang the tab — which is precisely the failure this
	// whole project is a reaction to.
	var MAX_ROWS = 500;
	var POLL_MS = 2000;

	function setStatus(text, cls) {
		if (!status) return;
		status.textContent = text;
		status.className = "live-status" + (cls ? " " + cls : "");
	}

	function severityBadge(sev) {
		var map = { 1: ["badge-danger", "high"], 2: ["badge-warning", "medium"], 3: ["badge-info", "low"] };
		var e = map[sev] || ["badge", "—"];
		var span = document.createElement("span");
		span.className = "badge " + e[0];
		span.textContent = e[1];
		return span;
	}

	function cell(text, cls) {
		var td = document.createElement("td");
		if (cls) td.className = cls;
		td.textContent = text;
		return td;
	}

	function localTime(iso) {
		var d = new Date(iso);
		if (isNaN(d.getTime())) return iso;
		var p = function (n) { return String(n).padStart(2, "0"); };
		return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) +
			" " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
	}

	// Rows are built with createElement and textContent throughout, never
	// innerHTML: every field here is attacker-controlled (a signature name, a
	// source address) and this page is where it is displayed most directly.
	function rowFor(ev) {
		var tr = document.createElement("tr");
		tr.className = "live-new";

		tr.appendChild(cell(localTime(ev.ts), "nowrap mono"));

		var src = document.createElement("td");
		src.className = "mono";
		var a = document.createElement("a");
		a.href = "/sources/" + encodeURIComponent(ev.srcIp);
		a.textContent = ev.srcIp;
		src.appendChild(a);
		tr.appendChild(src);

		var sig = document.createElement("td");
		var sid = document.createElement("span");
		sid.className = "mono";
		sid.textContent = ev.sid;
		sig.appendChild(sid);
		sig.appendChild(document.createTextNode(" " + (ev.signature || "")));
		tr.appendChild(sig);

		tr.appendChild(cell(ev.proto || "", "mono"));
		tr.appendChild(cell((ev.destIp || "") + (ev.destPort ? ":" + ev.destPort : ""), "mono"));

		var sev = document.createElement("td");
		sev.appendChild(severityBadge(ev.severity));
		tr.appendChild(sev);

		return tr;
	}

	function trim() {
		while (body.rows.length > MAX_ROWS) {
			body.deleteRow(body.rows.length - 1);
		}
	}

	function poll() {
		fetch("/api/events?after=" + cursor, { credentials: "same-origin" })
			.then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
			.then(function (data) {
				if (typeof data.cursor === "number") cursor = data.cursor;
				var events = data.events || [];
				if (events.length && follow && follow.checked) {
					var empty = document.getElementById("live-empty");
					if (empty) empty.remove();
					// The API returns oldest-first; prepending in that order
					// leaves the newest at the top.
					events.forEach(function (ev) {
						body.insertBefore(rowFor(ev), body.firstChild);
					});
					received += events.length;
					trim();
					if (countEl) countEl.textContent = received + " since this page loaded";
					// The filter box does not know about rows added after load.
					if (window.meerkatApplyFilter) window.meerkatApplyFilter();
				}
				setStatus(follow && follow.checked ? "live" : "paused", "ok");
			})
			.catch(function () {
				setStatus("reconnecting…", "bad");
			});
	}

	poll();
	setInterval(poll, POLL_MS);

	if (follow) {
		follow.addEventListener("change", function () {
			setStatus(follow.checked ? "live" : "paused", follow.checked ? "ok" : "");
		});
	}
})();
