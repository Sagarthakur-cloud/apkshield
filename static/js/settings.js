document.addEventListener("DOMContentLoaded", () => {
  const saveBar = document.getElementById("saveBar");
  if (!saveBar) return;

  const initialState = { toggles: [], threshold: 70 };

  document.querySelectorAll("[data-toggle]").forEach((el, i) => {
    initialState.toggles[i] = el.classList.contains("on");
    el.addEventListener("click", () => { el.classList.toggle("on"); check(); });
  });

  const slider = document.getElementById("riskThreshold");
  const sliderVal = document.getElementById("riskThresholdVal");
  if (slider) {
    slider.addEventListener("input", e => {
      sliderVal.textContent = e.target.value;
      check();
    });
  }

  function check() {
    let changed = false;
    document.querySelectorAll("[data-toggle]").forEach((el, i) => {
      if (el.classList.contains("on") !== initialState.toggles[i]) changed = true;
    });
    if (slider && parseInt(slider.value) !== initialState.threshold) changed = true;
    saveBar.classList.toggle("hidden", !changed);
  }

  document.getElementById("saveBtn").onclick = () => {
    document.querySelectorAll("[data-toggle]").forEach((el, i) => {
      initialState.toggles[i] = el.classList.contains("on");
    });
    if (slider) initialState.threshold = parseInt(slider.value);
    saveBar.classList.add("hidden");
    showToast("Settings saved", "success");
  };

  document.getElementById("cancelBtn").onclick = () => {
    document.querySelectorAll("[data-toggle]").forEach((el, i) => {
      el.classList.toggle("on", initialState.toggles[i]);
    });
    if (slider) { slider.value = initialState.threshold; sliderVal.textContent = initialState.threshold; }
    saveBar.classList.add("hidden");
    showToast("Changes discarded", "info");
  };

  const clearBtn = document.getElementById("clearAllHistoryBtn");
  if (clearBtn) clearBtn.onclick = () => {
    if (confirm("Are you sure? This will permanently delete all scan history.")) {
      showToast("All history cleared", "success");
    }
  };

  const resetBtn = document.getElementById("resetDefaultsBtn");
  if (resetBtn) resetBtn.onclick = () => {
    if (confirm("Reset all settings to defaults?")) {
      document.querySelectorAll("[data-toggle]").forEach((el, i) => {
        el.classList.toggle("on", [true, true, false, true][i] || false);
      });
      if (slider) { slider.value = 70; sliderVal.textContent = "70"; }
      check();
      showToast("Reset to defaults", "info");
    }
  };
});