/* Search only the encrypted documents already saved for offline access. */
window.OfflineAI = (() => {
  const stopWords = new Set(
    'a an and are can could did do does for from had has have how i in is it me my of on or please show tell that the their this to was were what when where which who will with would you your document documents pdf vault'.split(' ')
  );

  function words(text) {
    return text.normalize('NFKC').toLowerCase().match(/[\p{L}\p{N}]+/gu) || [];
  }

  function sessionStamp() {
    return JSON.stringify(['vaultSessionToken', 'vaultSession', 'vaultMode', 'vaultUser']
      .map(key => sessionStorage.getItem(key)));
  }

  function unlocked() {
    return Boolean(window.masterPassword &&
      (sessionStorage.getItem('vaultSessionToken') || sessionStorage.getItem('vaultSession')));
  }

  function visiblePDFs() {
    const visible = Object.values(window.allFilesData || {}).flatMap(files =>
      Array.isArray(files) ? window._filterFilesForMember(files) : []
    );
    const byPath = new Map();
    for (const file of visible) {
      if (typeof file?.file !== 'string' || /^\/?photos\//i.test(file.file)) continue;
      if (!/\.(pdf|enc)$/i.test(file.file)) continue;
      const members = Array.isArray(file.members) ? file.members : [file.member];
      const mode = sessionStorage.getItem('vaultMode') || window.VAULT_MODE;
      if (!mode || !members.some(member =>
        (mode === 'ADMIN' && member === 'official') ||
        (member && isMemberAllowedForCurrentMode(member))
      )) continue;
      byPath.set(file.file, file);
    }
    return [...byPath.values()];
  }

  async function ask(question) {
    if (/^(?:hi|hello|hey)[!.?\s]*$/i.test(question.trim())) {
      return { answer: 'Hi! Ask me about a PDF saved for offline access. I’ll show matching passages and page numbers.' };
    }
    if (!unlocked()) return { answer: 'Unlock the vault to search your documents.' };
    if (!window.pdfjsLib || typeof idbGetDoc !== 'function' ||
        typeof window._filterFilesForMember !== 'function' || typeof isMemberAllowedForCurrentMode !== 'function') {
      return { answer: 'The offline document reader is unavailable on this device.' };
    }

    const terms = [...new Set(words(question).filter(word => !stopWords.has(word)))].slice(0, 24);
    if (!terms.length) return { answer: 'Enter a specific name, date, or phrase from a document.' };

    const key = window.masterPassword;
    const stamp = sessionStamp();
    const files = visiblePDFs();
    const paths = JSON.stringify(files.map(file => file.file));
    const sessionIsCurrent = () =>
      unlocked() && window.masterPassword === key && sessionStamp() === stamp;
    const locked = { answer: 'The vault session changed. Ask again in the current session.' };
    const matches = [];
    let readablePages = 0;

    for (const file of files) {
      if (!sessionIsCurrent()) return locked;
      let task;
      try {
        const cached = await idbGetDoc(file.file);
        if (!cached) continue;
        const data = /\.enc$/i.test(file.file) ? await decryptVaultFile(cached) : cached;
        if (!sessionIsCurrent()) return locked;
        const bytes = new Uint8Array(data);
        // Some encrypted files are photos. Only send PDF bytes to the parser.
        if (!new TextDecoder().decode(bytes.subarray(0, 1024)).includes('%PDF-')) continue;
        window.pdfjsLib.GlobalWorkerOptions.workerSrc =
          new URL('/pdf.worker.min.js', location.origin).href;
        task = window.pdfjsLib.getDocument({
          data: bytes, isEvalSupported: false, useWorkerFetch: false, disableFontFace: true
        });
        const pdf = await task.promise;
        for (let number = 1; number <= pdf.numPages; number++) {
          if (!sessionIsCurrent()) return locked;
          const page = await pdf.getPage(number);
          const content = await page.getTextContent();
          const text = content.items.map(item => item.str || '').join(' ').trim();
          if (!text) continue;
          readablePages++;
          // Use overlapping passages to keep nearby lines and fields together.
          let best;
          for (let start = 0; start < text.length; start += 360) {
            const excerpt = text.slice(start, start + 540);
            const tokens = new Set(words(excerpt));
            const score = terms.filter(term => tokens.has(term)).length;
            if (score < Math.min(2, terms.length)) continue;
            if (!best || score > best.score) {
              best = { score, excerpt, number, name: file.name || file.file };
            }
          }
          if (best) {
            matches.push(best);
            matches.sort((a, b) => b.score - a.score);
            if (matches.length > 3) matches.pop();
          }
        }
      } catch {
        // A corrupt or unsupported file should not stop the remaining search.
      } finally {
        if (task) await task.destroy().catch(() => {});
      }
    }

    if (!sessionIsCurrent() || JSON.stringify(visiblePDFs().map(file => file.file)) !== paths) {
      return locked;
    }
    if (!readablePages) {
      return { answer: 'No readable PDFs are available offline. Save documents for offline access while connected. Image-only scans cannot be searched.' };
    }
    const excerpts = matches.map(match => `${match.name}, page ${match.number}\n“${match.excerpt}”`);
    return {
      answer: excerpts.length
        ? excerpts.join('\n\n')
        : 'I couldn’t find a matching passage in the PDFs saved on this device.'
    };
  }

  return { ask };
})();
