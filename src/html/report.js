(() => {
  const slot = document.querySelector(".source-slot");
  const stack = document.querySelector(".thread-list");
  const firstFrame = stack?.querySelector(".thread[open] .frame-link") || stack?.querySelector(".frame-link");
  if (!slot || !firstFrame) return;

  const preview = slot.querySelector("#source-preview");
  const locationLabel = preview.querySelector("#source-location");
  const message = preview.querySelector("#source-message");
  const compact = matchMedia("(max-width: 900px)");
  let selected;
  let visibleFile;
  let highlightedLine;

  for (const file of preview.querySelectorAll(".source-file")) file.hidden = true;
  preview.classList.add("is-interactive");

  function positionPreview() {
    if (compact.matches) {
      const entry = selected.closest(".frame-entry");
      if (entry.nextElementSibling !== preview) entry.after(preview);
    } else if (preview.parentElement !== slot) {
      slot.append(preview);
    }
  }

  function centerLine() {
    if (!highlightedLine) return;

    const scroll = highlightedLine.closest(".src");
    const top = highlightedLine.getBoundingClientRect().top - scroll.getBoundingClientRect().top;
    scroll.scrollTop += top - (scroll.clientHeight - highlightedLine.offsetHeight) / 2;
    scroll.scrollLeft = 0;
  }

  function selectFrame(frame) {
    frame.closest(".thread").open = true;
    selected?.removeAttribute("aria-current");
    frame.setAttribute("aria-current", "true");
    selected = frame;

    const target = document.getElementById(frame.hash.slice(1));
    const nextLine = target?.classList.contains("source-line") ? target : null;
    const nextFile = target?.closest(".source-file");
    if (visibleFile && visibleFile !== nextFile) visibleFile.hidden = true;
    if (nextFile) {
      nextFile.hidden = false;
      nextFile.open = true;
      if (!nextLine) nextFile.querySelector(".src")?.scrollTo(0, 0);
    }
    visibleFile = nextFile;
    highlightedLine?.classList.remove("current-line");
    highlightedLine = nextLine;
    highlightedLine?.classList.add("current-line");

    locationLabel.textContent = frame.dataset.location;
    locationLabel.hidden = !frame.dataset.location;
    message.hidden = Boolean(nextLine);
    message.textContent = frame.dataset.sourceMessage || "此帧的源码不可用。";

    positionPreview();
    centerLine();
  }

  function frameForFragment() {
    if (!/^#(?:src|source)-\d/.test(location.hash)) return null;
    return Array.from(stack.querySelectorAll(".frame-link")).find(frame => frame.hash === location.hash);
  }

  selectFrame(frameForFragment() || firstFrame);
  stack.addEventListener("click", event => {
    const frame = event.target.closest(".frame-link");
    if (!frame || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();

    // 移动内联面板时，让被点击的栈帧留在视口的原位置。
    const top = frame.getBoundingClientRect().top;
    selectFrame(frame);
    if (compact.matches) window.scrollBy(0, frame.getBoundingClientRect().top - top);
  });
  compact.addEventListener("change", () => {
    positionPreview();
    centerLine();
  });
  window.addEventListener("hashchange", () => {
    const frame = frameForFragment();
    if (frame) selectFrame(frame);
  });
})();
