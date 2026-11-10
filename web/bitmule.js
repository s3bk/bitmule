// The theme chooser on the marketing page: four buttons, one attribute.
//
// A file of its own rather than an inline <script>, because the page is served
// under a policy that lets no inline script run (see `security_headers` in
// bitmule-server). The same goes for bitmule.css.
var buttons = document.querySelectorAll("[data-theme-btn]");
buttons.forEach(function (btn) {
  btn.addEventListener("click", function () {
    var theme = btn.getAttribute("data-theme-btn");
    document.documentElement.setAttribute("data-theme", theme);
    buttons.forEach(function (b) {
      b.classList.remove("active");
    });
    btn.classList.add("active");
  });
});
