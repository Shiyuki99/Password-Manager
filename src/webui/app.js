const API_BASE = '';
let currentEntries = [];
let currentViewEntry = null;
let browseMode = 'open'; // 'open' or 'create'
let currentBrowsePath = '';

// Toast notifications
function showToast(message, type = 'success') {
   const container = document.getElementById('toastContainer');
   const toast = document.createElement('div');
   toast.className = `toast ${type}`;
   toast.innerHTML = `
        <span>${type === 'success' ? '✓' : '✕'}</span>
        <span>${message}</span>
    `;
   container.appendChild(toast);

   setTimeout(() => {
      toast.classList.add('hiding');
      setTimeout(() => toast.remove(), 300);
   }, 3000);
}

// Update UI state
function updateUI(vaultOpen, authenticated, vaultName = '', entries = 0) {
   document.getElementById('vaultStatus').classList.toggle('active', vaultOpen);
   document.getElementById('authStatus').classList.toggle('active', authenticated);
   document.getElementById('vaultStatusText').textContent = vaultOpen ? 'Open' : 'Closed';
   document.getElementById('authStatusText').textContent = authenticated ? 'Unlocked' : 'Locked';

   document.getElementById('createSection').style.display = vaultOpen ? 'none' : 'block';
   document.getElementById('openSection').style.display = vaultOpen ? 'none' : 'block';
   document.getElementById('authSection').style.display = vaultOpen && !authenticated ? 'block' : 'none';
   document.getElementById('actionsSection').style.display = authenticated ? 'block' : 'none';

   if (vaultOpen) {
      document.getElementById('vaultNameDisplay').textContent = vaultName;
      document.getElementById('vaultEntriesDisplay').textContent = `${entries} entries`;
      document.getElementById('vaultNameActive').textContent = vaultName;
      document.getElementById('vaultEntriesActive').textContent = `${entries} entries`;
   }
}

// File Browser
async function openFileBrowser(mode) {
   browseMode = mode;
   document.getElementById('browserTitle').textContent = mode === 'create' ? 'Choose Save Location' : 'Select Vault File';
   document.getElementById('newFileName').style.display = mode === 'create' ? 'block' : 'none';
   document.getElementById('browserSelect').textContent = mode === 'create' ? 'Save Here' : 'Open';

   await browsePath('~');
   document.getElementById('browserModal').classList.add('active');
}

async function browsePath(path) {
   try {
      const res = await fetch(`${API_BASE}/api/browse`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ path })
      });
      const data = await res.json();

      if (data.success) {
         currentBrowsePath = data.path;
         document.getElementById('currentPath').textContent = data.path;

         const list = document.getElementById('browserList');
         list.innerHTML = '';

         // Sort: directories first, then files
         const items = data.items.sort((a, b) => {
            if (a.is_dir && !b.is_dir) return -1;
            if (!a.is_dir && b.is_dir) return 1;
            return a.name.localeCompare(b.name);
         });

         for (const item of items) {
            const div = document.createElement('div');
            div.className = 'browser-item' + (item.is_dir ? ' is-dir' : '');
            div.innerHTML = `
                    <span class="browser-icon">${item.is_dir ? '📁' : '🔐'}</span>
                    <span class="browser-name">${item.name}</span>
                `;

            if (item.is_dir) {
               div.onclick = () => browsePath(item.path);
            } else {
               div.onclick = () => selectFile(item.path);
            }

            list.appendChild(div);
         }
      } else {
         showToast(data.error, 'error');
      }
   } catch (e) {
      showToast('Failed to browse directory', 'error');
   }
}

function selectFile(path) {
   document.querySelectorAll('.browser-item').forEach(el => el.classList.remove('selected'));
   event.currentTarget.classList.add('selected');
   currentBrowsePath = path;
}

function confirmBrowseSelection() {
   let finalPath = currentBrowsePath;

   if (browseMode === 'create') {
      const filename = document.getElementById('newFileNameInput').value || 'vault.shpd';
      const name = filename.endsWith('.shpd') ? filename : filename + '.shpd';
      finalPath = currentBrowsePath + (currentBrowsePath.endsWith('/') ? '' : '/') + name;
      document.getElementById('createPath').value = finalPath;
   } else {
      document.getElementById('openPath').value = finalPath;
   }

   closeModal('browserModal');
}

// API calls
async function createVault() {
   const name = document.getElementById('createName').value || 'My Vault';
   const password = document.getElementById('createPassword').value;
   const path = document.getElementById('createPath').value;

   if (!password || !path) {
      showToast('Please fill in all fields', 'error');
      return;
   }

   try {
      const res = await fetch(`${API_BASE}/api/vault/create`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ path, password, name })
      });
      const data = await res.json();

      if (data.success) {
         showToast('Vault created successfully');
         updateUI(true, true, data.name, data.entries);
         renderEntries([]);
      } else {
         showToast(data.error, 'error');
      }
   } catch (e) {
      showToast('Failed to create vault', 'error');
   }
}

async function openVault() {
   const path = document.getElementById('openPath').value;

   if (!path) {
      showToast('Please select a vault file', 'error');
      return;
   }

   try {
      const res = await fetch(`${API_BASE}/api/vault/open`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ path })
      });
      const data = await res.json();

      if (data.success) {
         showToast('Vault opened');
         updateUI(true, false, data.name, data.entries);
      } else {
         showToast(data.error, 'error');
      }
   } catch (e) {
      showToast('Failed to open vault', 'error');
   }
}

async function authenticate() {
   const password = document.getElementById('authPassword').value;

   if (!password) {
      showToast('Please enter password', 'error');
      return;
   }

   try {
      const res = await fetch(`${API_BASE}/api/vault/authenticate`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ password })
      });
      const data = await res.json();

      if (data.success) {
         showToast('Vault unlocked');
         const name = document.getElementById('vaultNameDisplay').textContent;
         const entries = document.getElementById('vaultEntriesDisplay').textContent;
         updateUI(true, true, name, parseInt(entries));
         loadEntries();
      } else {
         showToast(data.error, 'error');
      }
   } catch (e) {
      showToast('Authentication failed', 'error');
   }
}

async function closeVault() {
   try {
      const res = await fetch(`${API_BASE}/api/vault/close`, { method: 'POST' });
      const data = await res.json();

      if (data.success) {
         showToast('Vault closed');
         updateUI(false, false);
         currentEntries = [];
         renderEntries([]);
      }
   } catch (e) {
      showToast('Failed to close vault', 'error');
   }
}

async function loadEntries() {
   try {
      const res = await fetch(`${API_BASE}/api/entries/load`, { method: 'POST' });
      const data = await res.json();

      if (data.success) {
         const entriesRes = await fetch(`${API_BASE}/api/entries`);
         const entriesData = await entriesRes.json();

         if (entriesData.success) {
            currentEntries = entriesData.entries;
            renderEntries(currentEntries);
            document.getElementById('vaultEntriesActive').textContent = `${currentEntries.length} entries`;
         }
      } else {
         showToast(data.error, 'error');
      }
   } catch (e) {
      showToast('Failed to load entries', 'error');
   }
}

async function addEntry() {
   const entry = {
      name: document.getElementById('entryName').value,
      username: document.getElementById('entryUsername').value,
      password: document.getElementById('entryPassword').value,
      url: document.getElementById('entryUrl').value,
      notes: document.getElementById('entryNotes').value
   };

   if (!entry.name || !entry.password) {
      showToast('Name and password are required', 'error');
      return;
   }

   try {
      const res = await fetch(`${API_BASE}/api/entries/add`, {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify(entry)
      });
      const data = await res.json();

      if (data.success) {
         showToast('Entry added');
         closeModal('addModal');
         loadEntries();
         clearAddForm();
      } else {
         showToast(data.error, 'error');
      }
   } catch (e) {
      showToast('Failed to add entry', 'error');
   }
}

function clearAddForm() {
   document.getElementById('entryName').value = '';
   document.getElementById('entryUsername').value = '';
   document.getElementById('entryPassword').value = '';
   document.getElementById('entryUrl').value = '';
   document.getElementById('entryNotes').value = '';
}

function renderEntries(entries) {
   const grid = document.getElementById('entriesGrid');
   const count = document.getElementById('entriesCount');
   count.textContent = `${entries.length} items`;

   if (entries.length === 0) {
      grid.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📭</div>
                <h3>No entries yet</h3>
                <p>Add your first password entry</p>
            </div>
        `;
      return;
   }

   grid.innerHTML = entries.map((entry, index) => `
        <div class="entry-card" style="animation-delay: ${index * 0.05}s">
            <div class="entry-info">
                <div class="entry-name">${escapeHtml(entry.name)}</div>
                <div class="entry-username">${escapeHtml(entry.username || '-')}</div>
            </div>
            <div class="entry-actions">
                <button class="icon-btn" onclick="viewEntry(${index})" title="View">👁</button>
                <button class="icon-btn" onclick="copyEntryPassword(${index})" title="Copy password">📋</button>
            </div>
        </div>
    `).join('');
}

function filterEntries() {
   const search = document.getElementById('searchInput').value.toLowerCase();
   const filtered = currentEntries.filter(e =>
      e.name.toLowerCase().includes(search) ||
      (e.username && e.username.toLowerCase().includes(search))
   );
   renderEntries(filtered);
}

function openAddModal() {
   document.getElementById('addModal').classList.add('active');
   document.getElementById('entryName').focus();
}

function closeModal(id) {
   document.getElementById(id).classList.remove('active');
}

function viewEntry(index) {
   const entry = currentEntries[index];
   currentViewEntry = entry;

   document.getElementById('viewEntryTitle').textContent = entry.name;
   document.getElementById('viewUsername').textContent = entry.username || '-';
   document.getElementById('viewPassword').textContent = '••••••••';
   document.getElementById('viewPassword').style.filter = 'blur(8px)';
   document.getElementById('viewUrl').textContent = entry.url || '-';
   document.getElementById('viewNotes').textContent = entry.notes || '-';

   document.getElementById('viewModal').classList.add('active');
}

function toggleViewPassword() {
   const el = document.getElementById('viewPassword');
   if (el.style.filter === 'blur(8px)') {
      el.textContent = currentViewEntry.password;
      el.style.filter = 'none';
   } else {
      el.textContent = '••••••••';
      el.style.filter = 'blur(8px)';
   }
}

function copyPassword() {
   if (currentViewEntry) {
      navigator.clipboard.writeText(currentViewEntry.password);
      showToast('Password copied');
   }
}

function copyEntryPassword(index) {
   navigator.clipboard.writeText(currentEntries[index].password);
   showToast('Password copied');
}

function copyToClipboard(elementId) {
   const text = document.getElementById(elementId).textContent;
   navigator.clipboard.writeText(text);
   showToast('Copied to clipboard');
}

function togglePassword(inputId) {
   const input = document.getElementById(inputId);
   input.type = input.type === 'password' ? 'text' : 'password';
}

function generatePassword() {
   const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
   let password = '';
   for (let i = 0; i < 20; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
   }
   document.getElementById('entryPassword').value = password;
   showToast('Password generated');
}

function escapeHtml(text) {
   const div = document.createElement('div');
   div.textContent = text;
   return div.innerHTML;
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
   document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
         document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
      }
   });

   document.querySelectorAll('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', (e) => {
         if (e.target === overlay) {
            overlay.classList.remove('active');
         }
      });
   });

   document.getElementById('createPassword')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') createVault();
   });

   document.getElementById('authPassword')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') authenticate();
   });
});