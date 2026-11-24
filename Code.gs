/* ==========================================================================
   Code.gs — ระบบติดตามงานทีมห้องสมุด
   วิทยาลัยการอาชีพแม่สะเรียง

   วางโค้ดนี้ทั้งหมดใน Apps Script แล้วเรียกใช้ฟังก์ชัน setup() ครั้งเดียว
   จากนั้น Deploy → New deployment → Web app
     Execute as: Me · Who has access: Anyone
   ========================================================================== */

// ===================== CONFIG =====================
const LOCK_MAX = 5;            // ใส่รหัสผิดกี่ครั้งจึงล็อก
const LOCK_MIN = 15;           // ล็อกกี่นาที
const SESSION_HOURS = 6;       // เซสชันหมดอายุหลังไม่ได้ใช้กี่ชั่วโมง
const SESSION_SEC = SESSION_HOURS * 3600;
const MIN_PW = 8;
const SECRET_WORDS = /(password|passwd|secret|token|api[\s_\-]?key|private[\s_\-]?key|รหัสผ่าน|คีย์ลับ)/i;
const SECRET_KEYS = /(ghp_|github_pat_|AIza[0-9A-Za-z_\-]{20}|sk-[A-Za-z0-9]{16}|ya29\.|-----BEGIN)/;

// ===================== PEOPLE (ต้องตรงกับ PEOPLE ใน index.html) =====================
const PEOPLE = [
  ["cham","แชม","PM"],["ger","เกอร์","GitHub Master"],["first","เฟิร์ส","System Analyst"],
  ["lee","ลี","Data Engineer"],["ice","ไอซ์","Auth & Security"],["pai","ปาย","Frontend"],
  ["onew","ออนิว","Frontend"],["te","เต","Backend"],["wit","วิทย์","Backend"],
  ["baitong","ใบตอง","UX/UI"],["nana","นาน่า","Technical Writer"],["kwan","ขวัญ","QA Tester"]
];

// ===================== HELPERS =====================
function getSheet_(name) {
  return SpreadsheetApp.getActiveSpreadsheet().getSheetByName(name);
}

function uuid_() {
  return Utilities.getUuid();
}

function now_() {
  return new Date().toISOString();
}

function randomPassword_() {
  const chars = "abcdefghjkmnpqrstuvwxyz23456789";
  let pw = "";
  for (let i = 0; i < 10; i++) pw += chars[Math.floor(Math.random() * chars.length)];
  return pw;
}

function randomToken_() {
  return uuid_() + "-" + uuid_();
}

// ===================== HASHING (SHA-256 + salt) =====================
function makeSalt_() {
  const bytes = [];
  for (let i = 0; i < 16; i++) bytes.push(Math.floor(Math.random() * 256));
  return Utilities.base64Encode(bytes);
}

function hashPassword_(password, salt) {
  const raw = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, salt + ":" + password);
  return Utilities.base64Encode(raw);
}

function verifyPassword_(password, hash, salt) {
  return hashPassword_(password, salt) === hash;
}

// ===================== FORMULA INJECTION =====================
function sanitize_(val) {
  if (typeof val !== "string") return val;
  if (val.length > 0 && "=+-@\t\r\n".includes(val[0])) return "'" + val;
  return val;
}

// ===================== SHEET ↔ OBJECT =====================
function sheetToRows_(sheet) {
  if (!sheet || sheet.getLastRow() < 2) return [];
  const data = sheet.getDataRange().getValues();
  const headers = data[0];
  return data.slice(1).map((row, ri) => {
    const obj = { __row: ri + 2 };
    headers.forEach((h, ci) => { obj[h] = row[ci]; });
    return obj;
  });
}

function appendRow_(sheet, headers, obj) {
  const row = headers.map(h => sanitize_(obj[h] !== undefined ? obj[h] : ""));
  sheet.appendRow(row);
}

// ===================== SESSION CACHE =====================
function saveSession_(token, userId) {
  CacheService.getScriptCache().put("sess:" + token, userId, SESSION_SEC);
}

function getSession_(token) {
  if (!token) return null;
  return CacheService.getScriptCache().get("sess:" + token);
}

function deleteSession_(token) {
  if (!token) return;
  CacheService.getScriptCache().remove("sess:" + token);
}

function deleteAllSessions_(userId) {
  // CacheService ไม่มี listKeys ลบทีละรายการไม่ได้ ใช้วิธีเพิ่ม generation
  // เวลารีเซ็ตรหัสหรือปิดบัญชี จะเปลี่ยน generation ในแถว Users
  // แล้วตรวจ generation ตอน requireAuth_
  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  const headers = sheet.getDataRange().getValues()[0];
  const genCol = headers.indexOf("session_gen");
  if (genCol < 0) return;
  rows.forEach(r => {
    if (r.user_id === userId) {
      sheet.getRange(r.__row, genCol + 1).setValue((Number(r.session_gen) || 0) + 1);
    }
  });
}

// ===================== AUTH =====================
function requireAuth_(token) {
  if (!token) throw appError_("E_NO_TOKEN", "กรุณาเข้าสู่ระบบ");
  const userId = getSession_(token);
  if (!userId) throw appError_("E_SESSION_EXPIRED", "เซสชันหมดอายุ กรุณาเข้าสู่ระบบอีกครั้ง");
  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  const user = rows.find(r => r.user_id === userId && r.is_active === true);
  if (!user) {
    deleteSession_(token);
    throw appError_("E_SESSION_EXPIRED", "บัญชีถูกปิดหรือไม่พบผู้ใช้");
  }
  // Check session_gen — stored in cache as "gen:token"
  const cachedGen = CacheService.getScriptCache().get("gen:" + token);
  const currentGen = String(user.session_gen || 0);
  if (cachedGen !== null && cachedGen !== currentGen) {
    deleteSession_(token);
    throw appError_("E_SESSION_EXPIRED", "เซสชันถูกยกเลิก กรุณาเข้าสู่ระบบอีกครั้ง");
  }
  return { user, sheet, rows };
}

function requireRole_(user, ...roles) {
  if (!roles.includes(user.role)) throw appError_("E_FORBIDDEN", "คุณไม่มีสิทธิ์ใช้คำสั่งนี้");
}

function userPublic_(u) {
  return {
    user_id: u.user_id,
    username: u.username,
    display_name: u.display_name,
    person_key: u.person_key || "",
    role: u.role,
    must_change_password: u.must_change_password === true,
    is_active: u.is_active === true,
    last_login: u.last_login || ""
  };
}

// ===================== ERROR =====================
function appError_(code, message) {
  const e = new Error(message);
  e.appCode = code;
  return e;
}

// ===================== AUDIT LOG =====================
function audit_(userId, action, detail) {
  const sheet = getSheet_("AuditLog");
  if (!sheet) return;
  sheet.appendRow([now_(), userId, action, typeof detail === "object" ? JSON.stringify(detail) : String(detail || "")]);
}

// ===================== SETUP (เรียกครั้งเดียว) =====================
function setup() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  // Users
  let sh = ss.getSheetByName("Users");
  if (!sh) {
    sh = ss.insertSheet("Users");
    sh.appendRow(["user_id","username","display_name","person_key","role","password_hash","salt","is_active","must_change_password","last_login","failed_attempts","locked_until","session_gen","created_at"]);
  }
  // Create admin
  const users = sheetToRows_(sh);
  if (!users.some(u => u.username === "admin")) {
    const salt = makeSalt_();
    const tempPw = randomPassword_();
    const hash = hashPassword_(tempPw, salt);
    appendRow_(sh, ["user_id","username","display_name","person_key","role","password_hash","salt","is_active","must_change_password","last_login","failed_attempts","locked_until","session_gen","created_at"], {
      user_id: uuid_(),
      username: "admin",
      display_name: "ครูผู้ดูแล",
      person_key: "teacher",
      role: "admin",
      password_hash: hash,
      salt: salt,
      is_active: true,
      must_change_password: true,
      last_login: "",
      failed_attempts: 0,
      locked_until: "",
      session_gen: 0,
      created_at: now_()
    });
    Logger.log("ชื่อผู้ใช้: admin");
    Logger.log("รหัสผ่านชั่วคราว: " + tempPw);
  } else {
    Logger.log("บัญชี admin มีอยู่แล้ว ไม่ได้สร้างใหม่");
  }

  // Done
  if (!ss.getSheetByName("Done")) {
    const d = ss.insertSheet("Done");
    d.appendRow(["task_id","user_id","done_at"]);
  }

  // Notes
  if (!ss.getSheetByName("Notes")) {
    const n = ss.insertSheet("Notes");
    n.appendRow(["note_id","task_id","user_id","type","text","image_url","created_at"]);
  }

  // Resources
  if (!ss.getSheetByName("Resources")) {
    const r = ss.insertSheet("Resources");
    r.appendRow(["res_id","cat","label","value","note","owner","sort_order","updated_at","updated_by","created_at"]);
  }

  // CustomTasks (งานที่เพิ่มจากหน้าเว็บ)
  if (!ss.getSheetByName("CustomTasks")) {
    const ct = ss.insertSheet("CustomTasks");
    ct.appendRow(["task_id","week","owner","text","code","deps","created_by","created_at","subject_id"]);
  }

  // CustomPeople (สมาชิกที่เพิ่มจากหน้าเว็บ)
  if (!ss.getSheetByName("CustomPeople")) {
    const cp = ss.insertSheet("CustomPeople");
    cp.appendRow(["person_key","display_name","role_label","created_by","created_at","subject_id"]);
  }

  // Subjects (รายวิชา)
  if (!ss.getSheetByName("Subjects")) {
    const sb = ss.insertSheet("Subjects");
    sb.appendRow(["subject_id","name","code","semester","year","created_by","created_at","is_active"]);
    sb.appendRow(["default","งานทีมพัฒนาระบบห้องสมุด","LIB001","1","2569","system",now_(),true]);
  }

  // AuditLog
  if (!ss.getSheetByName("AuditLog")) {
    const a = ss.insertSheet("AuditLog");
    a.appendRow(["timestamp","user_id","action","detail"]);
  }

  // ลบ Sheet1 ถ้ามี
  const sheet1 = ss.getSheetByName("Sheet1");
  if (sheet1 && ss.getSheets().length > 1) {
    try { ss.deleteSheet(sheet1); } catch (e) {}
  }

  Logger.log("ตั้งค่าเสร็จสมบูรณ์ ดูรหัสผ่านชั่วคราวของ admin ด้านบน");
}

// ===================== RESET ADMIN PASSWORD =====================
function resetAdminPassword() {
  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  const headers = sheet.getDataRange().getValues()[0];
  const admin = rows.find(r => r.username === "admin");
  if (!admin) { Logger.log("ไม่พบบัญชี admin ให้รัน setup() ก่อน"); return; }

  const salt = makeSalt_();
  const tempPw = randomPassword_();
  const hash = hashPassword_(tempPw, salt);

  const colHash = headers.indexOf("password_hash") + 1;
  const colSalt = headers.indexOf("salt") + 1;
  const colMust = headers.indexOf("must_change_password") + 1;
  const colFailed = headers.indexOf("failed_attempts") + 1;
  const colLocked = headers.indexOf("locked_until") + 1;
  const colGen = headers.indexOf("session_gen") + 1;

  sheet.getRange(admin.__row, colHash).setValue(hash);
  sheet.getRange(admin.__row, colSalt).setValue(salt);
  sheet.getRange(admin.__row, colMust).setValue(true);
  sheet.getRange(admin.__row, colFailed).setValue(0);
  sheet.getRange(admin.__row, colLocked).setValue("");
  if (colGen > 0) sheet.getRange(admin.__row, colGen).setValue((Number(admin.session_gen) || 0) + 1);

  Logger.log("ชื่อผู้ใช้: admin");
  Logger.log("รหัสผ่านชั่วคราว: " + tempPw);
}

// ===================== WEB APP ENTRY =====================
function doPost(e) {
  try {
    const body = JSON.parse(e.postData.contents);
    const action = body.action;
    const token = body.token || null;
    const data = body.data || {};
    const result = route_(action, token, data);
    return jsonOk_(result);
  } catch (err) {
    const code = err.appCode || "E_SERVER";
    const message = err.appCode ? err.message : "เกิดข้อผิดพลาดภายในเซิร์ฟเวอร์";
    return jsonErr_(code, message);
  }
}

function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({ ok: true, data: "pong" }))
    .setMimeType(ContentService.MimeType.JSON);
}

function jsonOk_(data) {
  return ContentService.createTextOutput(JSON.stringify({ ok: true, data: data }))
    .setMimeType(ContentService.MimeType.JSON);
}

function jsonErr_(code, message) {
  return ContentService.createTextOutput(JSON.stringify({ ok: false, code: code, error: message }))
    .setMimeType(ContentService.MimeType.JSON);
}

// ===================== ROUTER =====================
function route_(action, token, data) {
  switch (action) {
    case "ping":        return { pong: true, time: now_() };
    case "login":       return doLogin_(data);
    case "logout":      return doLogout_(token);
    case "me":          return doMe_(token);
    case "changePassword": return doChangePassword_(token, data);
    case "getState":    return doGetState_(token, data);
    case "setDone":     return doSetDone_(token, data);
    case "addNote":     return doAddNote_(token, data);
    case "deleteNote":  return doDeleteNote_(token, data);
    case "saveResource":    return doSaveResource_(token, data);
    case "deleteResource":  return doDeleteResource_(token, data);
    case "listUsers":       return doListUsers_(token);
    case "createUser":      return doCreateUser_(token, data);
    case "createTeamAccounts": return doCreateTeamAccounts_(token);
    case "resetPassword":   return doResetPassword_(token, data);
    case "updateUser":      return doUpdateUser_(token, data);
    case "saveTask":        return doSaveTask_(token, data);
    case "deleteTask":      return doDeleteTask_(token, data);
    case "savePerson":      return doSavePerson_(token, data);
    case "deletePerson":    return doDeletePerson_(token, data);
    case "listSubjects":    return doListSubjects_(token);
    case "saveSubject":     return doSaveSubject_(token, data);
    case "deleteSubject":   return doDeleteSubject_(token, data);
    case "importUsers":     return doImportUsers_(token, data);
    default: throw appError_("E_BAD_ACTION", "ไม่รู้จักคำสั่ง " + action);
  }
}

// ===================== LOGIN =====================
function doLogin_(data) {
  const username = String(data.username || "").trim().toLowerCase();
  const password = String(data.password || "");
  if (!username || !password) throw appError_("E_BAD_INPUT", "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน");

  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  const headers = sheet.getDataRange().getValues()[0];
  const user = rows.find(r => r.username === username);

  if (!user || user.is_active !== true) throw appError_("E_LOGIN", "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");

  // ตรวจการล็อก
  if (user.locked_until) {
    const lockEnd = new Date(user.locked_until);
    if (new Date() < lockEnd) {
      const mins = Math.ceil((lockEnd - new Date()) / 60000);
      throw appError_("E_LOCKED", `บัญชีถูกล็อกชั่วคราว กรุณาลองใหม่ในอีก ${mins} นาที`);
    }
  }

  // ตรวจรหัสผ่าน
  if (!verifyPassword_(password, user.password_hash, user.salt)) {
    const attempts = (Number(user.failed_attempts) || 0) + 1;
    const colFailed = headers.indexOf("failed_attempts") + 1;
    sheet.getRange(user.__row, colFailed).setValue(attempts);

    if (attempts >= LOCK_MAX) {
      const colLocked = headers.indexOf("locked_until") + 1;
      const lockUntil = new Date(Date.now() + LOCK_MIN * 60000).toISOString();
      sheet.getRange(user.__row, colLocked).setValue(lockUntil);
      sheet.getRange(user.__row, colFailed).setValue(0);
      throw appError_("E_LOCKED", `ใส่รหัสผ่านผิดครบ ${LOCK_MAX} ครั้ง บัญชีถูกล็อก ${LOCK_MIN} นาที`);
    }

    throw appError_("E_LOGIN", `ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง (ผิด ${attempts}/${LOCK_MAX} ครั้ง)`);
  }

  // รหัสถูก — รีเซ็ต failed_attempts
  const colFailed = headers.indexOf("failed_attempts") + 1;
  const colLocked = headers.indexOf("locked_until") + 1;
  const colLogin = headers.indexOf("last_login") + 1;
  sheet.getRange(user.__row, colFailed).setValue(0);
  sheet.getRange(user.__row, colLocked).setValue("");
  sheet.getRange(user.__row, colLogin).setValue(now_());

  const token = randomToken_();
  saveSession_(token, user.user_id);
  // Store generation in cache for this session
  CacheService.getScriptCache().put("gen:" + token, String(user.session_gen || 0), SESSION_SEC);

  audit_(user.user_id, "login", user.username);

  return { token: token, user: userPublic_(user) };
}

// ===================== LOGOUT =====================
function doLogout_(token) {
  if (token) {
    const userId = getSession_(token);
    deleteSession_(token);
    CacheService.getScriptCache().remove("gen:" + token);
    if (userId) audit_(userId, "logout", "");
  }
  return { ok: true };
}

// ===================== ME =====================
function doMe_(token) {
  const { user } = requireAuth_(token);
  if (user.must_change_password === true) throw appError_("E_MUST_CHANGE", "กรุณาตั้งรหัสผ่านใหม่ก่อนใช้งาน");
  return userPublic_(user);
}

// ===================== CHANGE PASSWORD =====================
function doChangePassword_(token, data) {
  const { user, sheet, rows } = requireAuth_(token);
  const oldPw = String(data.old_password || "");
  const newPw = String(data.new_password || "");

  if (!verifyPassword_(oldPw, user.password_hash, user.salt)) {
    throw appError_("E_BAD_INPUT", "รหัสผ่านเดิมไม่ถูกต้อง");
  }
  if (newPw.length < MIN_PW) {
    throw appError_("E_BAD_INPUT", "รหัสผ่านใหม่ต้องยาวอย่างน้อย " + MIN_PW + " ตัวอักษร");
  }

  const salt = makeSalt_();
  const hash = hashPassword_(newPw, salt);
  const headers = sheet.getDataRange().getValues()[0];

  sheet.getRange(user.__row, headers.indexOf("password_hash") + 1).setValue(hash);
  sheet.getRange(user.__row, headers.indexOf("salt") + 1).setValue(salt);
  sheet.getRange(user.__row, headers.indexOf("must_change_password") + 1).setValue(false);

  audit_(user.user_id, "changePassword", user.username);

  user.must_change_password = false;
  return userPublic_(user);
}

// ===================== GET STATE =====================
function doGetState_(token, data) {
  const { user } = requireAuth_(token);
  if (user.must_change_password === true) throw appError_("E_MUST_CHANGE", "กรุณาตั้งรหัสผ่านใหม่ก่อนใช้งาน");

  const subjectId = String((data && data.subject_id) || "default");

  // Subjects
  const subSheet = getSheet_("Subjects");
  const subjects = subSheet ? sheetToRows_(subSheet).filter(s => s.is_active === true).map(s => ({
    subject_id: s.subject_id,
    name: s.name,
    code: s.code || "",
    semester: s.semester || "",
    year: s.year || ""
  })) : [{ subject_id: "default", name: "งานทีมพัฒนาระบบห้องสมุด", code: "LIB001", semester: "1", year: "2569" }];

  // People
  const usersSheet = getSheet_("Users");
  const allUsers = sheetToRows_(usersSheet).filter(u => u.is_active === true);
  const people = allUsers.map(u => ({
    user_id: u.user_id,
    display_name: u.display_name,
    person_key: u.person_key || "",
    role: u.role
  }));

  // Done
  const doneSheet = getSheet_("Done");
  const done = sheetToRows_(doneSheet).map(d => ({
    task_id: d.task_id,
    user_id: d.user_id,
    done_at: d.done_at
  }));

  // Notes
  const notesSheet = getSheet_("Notes");
  const notes = sheetToRows_(notesSheet).map(n => ({
    note_id: n.note_id,
    task_id: n.task_id,
    user_id: n.user_id,
    type: n.type,
    text: n.text,
    image_url: n.image_url || "",
    created_at: n.created_at
  }));

  // Resources
  const resSheet = getSheet_("Resources");
  const resources = sheetToRows_(resSheet).map(r => ({
    res_id: r.res_id,
    cat: r.cat,
    label: r.label,
    value: r.value,
    note: r.note,
    owner: r.owner || "",
    sort_order: Number(r.sort_order) || 0,
    updated_at: r.updated_at,
    updated_by: r.updated_by
  }));

  // Custom Tasks (filtered by subject)
  const ctSheet = getSheet_("CustomTasks");
  const customTasks = ctSheet ? sheetToRows_(ctSheet)
    .filter(t => !t.subject_id || t.subject_id === subjectId)
    .map(t => ({
      id: t.task_id,
      w: Number(t.week),
      who: t.owner,
      text: t.text,
      code: t.code || "",
      deps: t.deps ? String(t.deps).split(",").filter(Boolean) : [],
      custom: true,
      created_by: t.created_by,
      subject_id: t.subject_id || "default"
    })) : [];

  // Custom People (filtered by subject)
  const cpSheet = getSheet_("CustomPeople");
  const customPeople = cpSheet ? sheetToRows_(cpSheet)
    .filter(p => !p.subject_id || p.subject_id === subjectId)
    .map(p => ({
      key: p.person_key,
      name: p.display_name,
      role: p.role_label || ""
    })) : [];

  return {
    me: userPublic_(user),
    people: people,
    done: done,
    notes: notes,
    resources: resources,
    custom_tasks: customTasks,
    custom_people: customPeople,
    subjects: subjects,
    current_subject: subjectId
  };
}

// ===================== SET DONE =====================
function doSetDone_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin", "member");
  if (user.must_change_password === true) throw appError_("E_MUST_CHANGE", "กรุณาตั้งรหัสผ่านใหม่ก่อนใช้งาน");

  const taskId = String(data.task_id || "");
  const done = data.done === true;
  if (!taskId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุรหัสงาน");

  const sheet = getSheet_("Done");
  const rows = sheetToRows_(sheet);

  if (done) {
    // เพิ่ม (ถ้ายังไม่มี)
    if (!rows.some(r => r.task_id === taskId)) {
      appendRow_(sheet, ["task_id","user_id","done_at"], {
        task_id: taskId,
        user_id: user.user_id,
        done_at: now_()
      });
    }
  } else {
    const existing = rows.find(r => r.task_id === taskId);
    if (existing) {
      sheet.deleteRow(existing.__row);
    }
  }

  return doGetState_(token, data);
}

// ===================== ADD NOTE =====================
function doAddNote_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin", "member");
  if (user.must_change_password === true) throw appError_("E_MUST_CHANGE", "กรุณาตั้งรหัสผ่านใหม่ก่อนใช้งาน");

  const taskId = String(data.task_id || "");
  const type = String(data.type || "other");
  let text = String(data.text || "").trim();
  if (!taskId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุรหัสงาน");
  if (!text) throw appError_("E_BAD_INPUT", "กรุณาเขียนข้อความบันทึก");
  if (text.length > 1000) text = text.slice(0, 1000);

  let imageUrl = String(data.image_url || "").trim();
  if (imageUrl.length > 50000) imageUrl = imageUrl.slice(0, 50000); // จำกัดขนาด base64

  const sheet = getSheet_("Notes");
  appendRow_(sheet, ["note_id","task_id","user_id","type","text","image_url","created_at"], {
    note_id: uuid_(),
    task_id: taskId,
    user_id: user.user_id,
    type: type,
    text: text,
    image_url: imageUrl,
    created_at: now_()
  });

  return doGetState_(token, data);
}

// ===================== DELETE NOTE =====================
function doDeleteNote_(token, data) {
  const { user } = requireAuth_(token);
  if (user.must_change_password === true) throw appError_("E_MUST_CHANGE", "กรุณาตั้งรหัสผ่านใหม่ก่อนใช้งาน");

  const noteId = String(data.note_id || "");
  if (!noteId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุรหัสบันทึก");

  const sheet = getSheet_("Notes");
  const rows = sheetToRows_(sheet);
  const note = rows.find(r => r.note_id === noteId);
  if (!note) throw appError_("E_NOT_FOUND", "ไม่พบบันทึกนี้");

  // สมาชิกลบได้เฉพาะของตัวเอง ผู้ดูแลลบได้ทั้งหมด
  if (user.role !== "admin" && note.user_id !== user.user_id) {
    throw appError_("E_FORBIDDEN", "คุณลบบันทึกของคนอื่นไม่ได้");
  }

  sheet.deleteRow(note.__row);
  audit_(user.user_id, "deleteNote", { note_id: noteId, task_id: note.task_id, text: note.text.slice(0, 100) });

  return doGetState_(token, data);
}

// ===================== SAVE RESOURCE =====================
function doSaveResource_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin", "member");
  if (user.must_change_password === true) throw appError_("E_MUST_CHANGE", "กรุณาตั้งรหัสผ่านใหม่ก่อนใช้งาน");

  let label = String(data.label || "").trim();
  let value = String(data.value || "").trim();
  let note = String(data.note || "").trim();
  const cat = String(data.cat || "อื่นๆ").trim();
  const owner = String(data.owner || "");

  if (!label) throw appError_("E_BAD_INPUT", "กรุณาใส่ชื่อรายการ");
  if (label.length > 120) label = label.slice(0, 120);
  if (value.length > 500) value = value.slice(0, 500);
  if (note.length > 300) note = note.slice(0, 300);

  // ตรวจความลับ
  if (SECRET_WORDS.test(label + " " + note) || SECRET_KEYS.test(value)) {
    throw appError_("E_SECRET", "รายการนี้ดูเหมือนรหัสผ่านหรือคีย์ลับ ห้ามเก็บในข้อมูลกลาง ให้เก็บใน Script Properties ของ GAS");
  }

  const sheet = getSheet_("Resources");
  const resId = String(data.res_id || "");

  if (resId) {
    // แก้ไข
    const rows = sheetToRows_(sheet);
    const headers = sheet.getDataRange().getValues()[0];
    const existing = rows.find(r => r.res_id === resId);
    if (!existing) throw appError_("E_NOT_FOUND", "ไม่พบรายการนี้");

    const setCol = (name, val) => { const c = headers.indexOf(name); if (c >= 0) sheet.getRange(existing.__row, c + 1).setValue(sanitize_(val)); };
    setCol("cat", cat);
    setCol("label", label);
    setCol("value", value);
    setCol("note", note);
    setCol("owner", owner);
    setCol("updated_at", now_());
    setCol("updated_by", user.user_id);
  } else {
    // สร้างใหม่
    const rows = sheetToRows_(sheet);
    const sortOrder = rows.length > 0 ? Math.max(...rows.map(r => Number(r.sort_order) || 0)) + 1 : 1;
    appendRow_(sheet, ["res_id","cat","label","value","note","owner","sort_order","updated_at","updated_by","created_at"], {
      res_id: uuid_(),
      cat: cat,
      label: label,
      value: value,
      note: note,
      owner: owner,
      sort_order: sortOrder,
      updated_at: now_(),
      updated_by: user.user_id,
      created_at: now_()
    });
  }

  return doGetState_(token, data);
}

// ===================== DELETE RESOURCE =====================
function doDeleteResource_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin", "member");
  if (user.must_change_password === true) throw appError_("E_MUST_CHANGE", "กรุณาตั้งรหัสผ่านใหม่ก่อนใช้งาน");

  const resId = String(data.res_id || "");
  if (!resId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุรหัสรายการ");

  const sheet = getSheet_("Resources");
  const rows = sheetToRows_(sheet);
  const existing = rows.find(r => r.res_id === resId);
  if (!existing) throw appError_("E_NOT_FOUND", "ไม่พบรายการนี้");

  sheet.deleteRow(existing.__row);
  audit_(user.user_id, "deleteResource", { res_id: resId, label: existing.label });

  return doGetState_(token, data);
}

// ===================== LIST USERS (admin) =====================
function doListUsers_(token) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  return rows.map(u => userPublic_(u));
}

// ===================== CREATE USER (admin) =====================
function doCreateUser_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const username = String(data.username || "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_.\-]{1,31}$/.test(username)) {
    throw appError_("E_BAD_INPUT", "ชื่อผู้ใช้ใช้ได้เฉพาะ a-z 0-9 _ . - ยาว 2–32 ตัว");
  }
  const displayName = String(data.display_name || "").trim();
  if (!displayName) throw appError_("E_BAD_INPUT", "กรุณาใส่ชื่อที่แสดง");

  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  if (rows.some(r => r.username === username)) {
    throw appError_("E_DUPLICATE", "ชื่อผู้ใช้ " + username + " มีอยู่แล้ว");
  }

  const salt = makeSalt_();
  const tempPw = randomPassword_();
  const hash = hashPassword_(tempPw, salt);

  const newUser = {
    user_id: uuid_(),
    username: username,
    display_name: displayName,
    person_key: data.person_key || "",
    role: data.role || "member",
    password_hash: hash,
    salt: salt,
    is_active: true,
    must_change_password: true,
    last_login: "",
    failed_attempts: 0,
    locked_until: "",
    session_gen: 0,
    created_at: now_()
  };

  appendRow_(sheet, ["user_id","username","display_name","person_key","role","password_hash","salt","is_active","must_change_password","last_login","failed_attempts","locked_until","session_gen","created_at"], newUser);
  audit_(user.user_id, "createUser", { username, display_name: displayName, role: newUser.role });

  const allUsers = sheetToRows_(sheet).map(u => userPublic_(u));
  return {
    users: allUsers,
    created: [{ username: username, display_name: displayName, temp_password: tempPw }]
  };
}

// ===================== CREATE TEAM ACCOUNTS (admin) =====================
function doCreateTeamAccounts_(token) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const sheet = getSheet_("Users");
  let rows = sheetToRows_(sheet);
  const created = [];

  PEOPLE.forEach(([key, name, role]) => {
    if (key === "teacher") return; // ครูมีบัญชี admin แล้ว
    if (rows.some(r => r.person_key === key)) return; // มีบัญชีแล้ว

    const salt = makeSalt_();
    const tempPw = randomPassword_();
    const hash = hashPassword_(tempPw, salt);

    appendRow_(sheet, ["user_id","username","display_name","person_key","role","password_hash","salt","is_active","must_change_password","last_login","failed_attempts","locked_until","session_gen","created_at"], {
      user_id: uuid_(),
      username: key,
      display_name: name,
      person_key: key,
      role: "member",
      password_hash: hash,
      salt: salt,
      is_active: true,
      must_change_password: true,
      last_login: "",
      failed_attempts: 0,
      locked_until: "",
      session_gen: 0,
      created_at: now_()
    });

    created.push({ username: key, display_name: name, temp_password: tempPw });
  });

  if (created.length > 0) {
    audit_(user.user_id, "createTeamAccounts", created.map(c => c.username).join(", "));
  }

  rows = sheetToRows_(sheet);
  return {
    users: rows.map(u => userPublic_(u)),
    created: created
  };
}

// ===================== RESET PASSWORD (admin) =====================
function doResetPassword_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const targetId = String(data.user_id || "");
  if (!targetId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุผู้ใช้");

  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  const headers = sheet.getDataRange().getValues()[0];
  const target = rows.find(r => r.user_id === targetId);
  if (!target) throw appError_("E_NOT_FOUND", "ไม่พบผู้ใช้");

  const salt = makeSalt_();
  const tempPw = randomPassword_();
  const hash = hashPassword_(tempPw, salt);

  const setCol = (name, val) => { const c = headers.indexOf(name); if (c >= 0) sheet.getRange(target.__row, c + 1).setValue(val); };
  setCol("password_hash", hash);
  setCol("salt", salt);
  setCol("must_change_password", true);
  setCol("failed_attempts", 0);
  setCol("locked_until", "");
  setCol("session_gen", (Number(target.session_gen) || 0) + 1);

  audit_(user.user_id, "resetPassword", { target_username: target.username });

  const allUsers = sheetToRows_(sheet).map(u => userPublic_(u));
  return {
    users: allUsers,
    created: [{ username: target.username, display_name: target.display_name, temp_password: tempPw }]
  };
}

// ===================== UPDATE USER (admin) =====================
function doUpdateUser_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const targetId = String(data.user_id || "");
  if (!targetId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุผู้ใช้");

  const sheet = getSheet_("Users");
  const rows = sheetToRows_(sheet);
  const headers = sheet.getDataRange().getValues()[0];
  const target = rows.find(r => r.user_id === targetId);
  if (!target) throw appError_("E_NOT_FOUND", "ไม่พบผู้ใช้");

  const changes = {};
  const setCol = (name, val) => { const c = headers.indexOf(name); if (c >= 0) sheet.getRange(target.__row, c + 1).setValue(val); changes[name] = val; };

  if (data.display_name !== undefined) setCol("display_name", String(data.display_name).trim());
  if (data.person_key !== undefined) setCol("person_key", String(data.person_key));
  if (data.role !== undefined && targetId !== user.user_id) setCol("role", String(data.role));

  if (data.is_active !== undefined) {
    setCol("is_active", data.is_active === true);
    if (data.is_active === false) {
      // ปิดบัญชี → ยกเลิกทุกเซสชัน
      setCol("session_gen", (Number(target.session_gen) || 0) + 1);
    }
  }

  audit_(user.user_id, "updateUser", { target_username: target.username, changes });

  const allUsers = sheetToRows_(sheet).map(u => userPublic_(u));
  return { users: allUsers };
}

// ===================== SAVE TASK (admin) =====================
function doSaveTask_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const week = Number(data.week);
  if (!week || week < 1 || week > 20) throw appError_("E_BAD_INPUT", "สัปดาห์ต้องเป็นตัวเลข 1–20");
  let text = String(data.text || "").trim();
  if (!text) throw appError_("E_BAD_INPUT", "กรุณาใส่รายละเอียดงาน");
  if (text.length > 500) text = text.slice(0, 500);
  const owner = String(data.owner || "");
  const code = String(data.code || "").trim();
  const deps = String(data.deps || "");
  const taskId = String(data.task_id || "");

  const sheet = getSheet_("CustomTasks");
  if (!sheet) throw appError_("E_SERVER", "ไม่พบแท็บ CustomTasks ให้รัน setup() อีกครั้ง");

  if (taskId) {
    // แก้ไข
    const rows = sheetToRows_(sheet);
    const headers = sheet.getDataRange().getValues()[0];
    const existing = rows.find(r => r.task_id === taskId);
    if (!existing) throw appError_("E_NOT_FOUND", "ไม่พบงานนี้");
    const setCol = (name, val) => { const c = headers.indexOf(name); if (c >= 0) sheet.getRange(existing.__row, c + 1).setValue(sanitize_(val)); };
    setCol("week", week);
    setCol("owner", owner);
    setCol("text", text);
    setCol("code", code);
    setCol("deps", deps);
  } else {
    // สร้างใหม่
    const newId = "ct" + Date.now();
    const subjectId = String(data.subject_id || "default");
    appendRow_(sheet, ["task_id","week","owner","text","code","deps","created_by","created_at","subject_id"], {
      task_id: newId, week: week, owner: owner, text: text,
      code: code, deps: deps, created_by: user.user_id, created_at: now_(), subject_id: subjectId
    });
    audit_(user.user_id, "addTask", { task_id: newId, text: text.slice(0, 60) });
  }
  return doGetState_(token, data);
}

// ===================== DELETE TASK (admin) =====================
function doDeleteTask_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const taskId = String(data.task_id || "");
  if (!taskId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุรหัสงาน");

  const sheet = getSheet_("CustomTasks");
  const rows = sheetToRows_(sheet);
  const existing = rows.find(r => r.task_id === taskId);
  if (!existing) throw appError_("E_NOT_FOUND", "ไม่พบงานนี้ (ลบได้เฉพาะงานที่เพิ่มจากหน้าเว็บ)");

  sheet.deleteRow(existing.__row);
  audit_(user.user_id, "deleteTask", { task_id: taskId, text: existing.text });
  return doGetState_(token, data);
}

// ===================== SAVE PERSON (admin) =====================
function doSavePerson_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  let key = String(data.person_key || "").trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_.-]{0,31}$/.test(key)) throw appError_("E_BAD_INPUT", "รหัสสมาชิกใช้ a-z 0-9 เท่านั้น");
  let name = String(data.display_name || "").trim();
  if (!name) throw appError_("E_BAD_INPUT", "กรุณาใส่ชื่อ");
  if (name.length > 60) name = name.slice(0, 60);
  const roleLabel = String(data.role_label || "").trim().slice(0, 60);

  const sheet = getSheet_("CustomPeople");
  if (!sheet) throw appError_("E_SERVER", "ไม่พบแท็บ CustomPeople ให้รัน setup() อีกครั้ง");

  const rows = sheetToRows_(sheet);
  const existing = rows.find(r => r.person_key === key);

  if (existing) {
    const headers = sheet.getDataRange().getValues()[0];
    const setCol = (n, v) => { const c = headers.indexOf(n); if (c >= 0) sheet.getRange(existing.__row, c + 1).setValue(sanitize_(v)); };
    setCol("display_name", name);
    setCol("role_label", roleLabel);
  } else {
    const subjectId = String(data.subject_id || "default");
    appendRow_(sheet, ["person_key","display_name","role_label","created_by","created_at","subject_id"], {
      person_key: key, display_name: name, role_label: roleLabel,
      created_by: user.user_id, created_at: now_(), subject_id: subjectId
    });
    audit_(user.user_id, "addPerson", { person_key: key, display_name: name });
  }
  return doGetState_(token, data);
}

// ===================== DELETE PERSON (admin) =====================
function doDeletePerson_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const key = String(data.person_key || "");
  if (!key) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุรหัสสมาชิก");

  const sheet = getSheet_("CustomPeople");
  const rows = sheetToRows_(sheet);
  const existing = rows.find(r => r.person_key === key);
  if (!existing) throw appError_("E_NOT_FOUND", "ไม่พบสมาชิกนี้ (ลบได้เฉพาะสมาชิกที่เพิ่มจากหน้าเว็บ)");

  sheet.deleteRow(existing.__row);
  audit_(user.user_id, "deletePerson", { person_key: key });
  return doGetState_(token, data);
}

// ===================== LIST SUBJECTS =====================
function doListSubjects_(token) {
  const { user } = requireAuth_(token);
  const sheet = getSheet_("Subjects");
  if (!sheet) return [];
  return sheetToRows_(sheet).map(s => ({
    subject_id: s.subject_id,
    name: s.name,
    code: s.code || "",
    semester: s.semester || "",
    year: s.year || "",
    is_active: s.is_active === true,
    created_by: s.created_by || ""
  }));
}

// ===================== SAVE SUBJECT (admin) =====================
function doSaveSubject_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  let name = String(data.name || "").trim();
  if (!name) throw appError_("E_BAD_INPUT", "กรุณาใส่ชื่อรายวิชา");
  if (name.length > 120) name = name.slice(0, 120);
  const code = String(data.code || "").trim().slice(0, 30);
  const semester = String(data.semester || "").trim().slice(0, 10);
  const year = String(data.year || "").trim().slice(0, 10);
  const subjectId = String(data.subject_id || "");

  const sheet = getSheet_("Subjects");
  if (!sheet) throw appError_("E_SERVER", "ไม่พบแท็บ Subjects ให้รัน setup() อีกครั้ง");

  if (subjectId) {
    const rows = sheetToRows_(sheet);
    const headers = sheet.getDataRange().getValues()[0];
    const existing = rows.find(r => r.subject_id === subjectId);
    if (!existing) throw appError_("E_NOT_FOUND", "ไม่พบรายวิชานี้");
    const setCol = (n, v) => { const c = headers.indexOf(n); if (c >= 0) sheet.getRange(existing.__row, c + 1).setValue(sanitize_(v)); };
    setCol("name", name);
    setCol("code", code);
    setCol("semester", semester);
    setCol("year", year);
  } else {
    const newId = "sub" + Date.now();
    appendRow_(sheet, ["subject_id","name","code","semester","year","created_by","created_at","is_active"], {
      subject_id: newId, name: name, code: code, semester: semester, year: year,
      created_by: user.user_id, created_at: now_(), is_active: true
    });
    audit_(user.user_id, "addSubject", { subject_id: newId, name: name });
  }

  return doListSubjects_(token);
}

// ===================== DELETE SUBJECT (admin) =====================
function doDeleteSubject_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const subjectId = String(data.subject_id || "");
  if (!subjectId) throw appError_("E_BAD_INPUT", "ไม่ได้ระบุรายวิชา");
  if (subjectId === "default") throw appError_("E_FORBIDDEN", "ไม่สามารถลบรายวิชาเริ่มต้นได้");

  const sheet = getSheet_("Subjects");
  const rows = sheetToRows_(sheet);
  const headers = sheet.getDataRange().getValues()[0];
  const existing = rows.find(r => r.subject_id === subjectId);
  if (!existing) throw appError_("E_NOT_FOUND", "ไม่พบรายวิชานี้");

  const isActiveCol = headers.indexOf("is_active");
  if (isActiveCol >= 0) sheet.getRange(existing.__row, isActiveCol + 1).setValue(false);
  audit_(user.user_id, "deleteSubject", { subject_id: subjectId, name: existing.name });

  return doListSubjects_(token);
}

// ===================== IMPORT USERS (admin) =====================
function doImportUsers_(token, data) {
  const { user } = requireAuth_(token);
  requireRole_(user, "admin");

  const rows = data.users;
  if (!Array.isArray(rows) || !rows.length) throw appError_("E_BAD_INPUT", "ไม่มีข้อมูลผู้ใช้ที่จะนำเข้า");
  if (rows.length > 200) throw appError_("E_BAD_INPUT", "นำเข้าได้ไม่เกิน 200 คนต่อครั้ง");

  const sheet = getSheet_("Users");
  const existing = sheetToRows_(sheet);
  const headers = ["user_id","username","display_name","person_key","role","password_hash","salt","is_active","must_change_password","last_login","failed_attempts","locked_until","session_gen","created_at"];
  const created = [];
  const skipped = [];

  rows.forEach(r => {
    let username = String(r.username || "").trim().toLowerCase().replace(/[^a-z0-9_.@-]/g, "");
    if (!username || username.length < 2) { skipped.push({ name: r.display_name || "?", reason: "ชื่อผู้ใช้ไม่ถูกต้อง" }); return; }
    if (username.length > 32) username = username.slice(0, 32);
    const displayName = String(r.display_name || "").trim();
    if (!displayName) { skipped.push({ name: username, reason: "ไม่มีชื่อที่แสดง" }); return; }
    if (existing.some(u => u.username === username)) { skipped.push({ name: displayName, reason: "ชื่อผู้ใช้ซ้ำ" }); return; }

    const salt = makeSalt_();
    const tempPw = randomPassword_();
    const hash = hashPassword_(tempPw, salt);

    const newUser = {
      user_id: uuid_(), username: username, display_name: displayName,
      person_key: r.person_key || "", role: r.role || "member",
      password_hash: hash, salt: salt, is_active: true,
      must_change_password: true, last_login: "", failed_attempts: 0,
      locked_until: "", session_gen: 0, created_at: now_()
    };
    appendRow_(sheet, headers, newUser);
    existing.push({ username: username });
    created.push({ username: username, display_name: displayName, temp_password: tempPw });
  });

  if (created.length > 0) {
    audit_(user.user_id, "importUsers", { count: created.length, skipped: skipped.length });
  }

  const allUsers = sheetToRows_(sheet).map(u => userPublic_(u));
  return { users: allUsers, created: created, skipped: skipped };
}
