import streamlit as st
st.set_page_config(page_title="Secure Biometric System", layout="centered")

import os
import numpy as np
from PIL import Image
from datetime import datetime

from image_processing import generate_binary_template
from bloom_filter import BloomFilter
from fpe_encrypt import FPE
from matcher import hamming_similarity
import matplotlib.pyplot as plt
from db import get_db


# ----------------- HELPERS -----------------
def add_log(message):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.logs.insert(0, f"{time} — {message}")


# ----------------- SESSION STATE -----------------
if "page" not in st.session_state:
    st.session_state.page = "home"
if "user" not in st.session_state:
    st.session_state.user = None
if "logs" not in st.session_state:
    st.session_state.logs = []
if "failures" not in st.session_state:
    st.session_state.failures = {}
if "last_failed_user" not in st.session_state:
    st.session_state.last_failed_user = None
if "reauth_required" not in st.session_state:
    st.session_state.reauth_required = False
if "vault_action" not in st.session_state:
    st.session_state.vault_action = None
if "locked_user" not in st.session_state:
    st.session_state.locked_user = None
if "show_continue" not in st.session_state:
    st.session_state.show_continue = False
if "auth_success" not in st.session_state:
    st.session_state.auth_success = False
if "login_success" not in st.session_state:
    st.session_state.login_success = False


# ----------------- CSS -----------------
st.markdown("""
<style>
/* Background */
.stApp {
    background: linear-gradient(120deg, #f6f9ff, #eef2ff);
}

/* Card container */
.card {
    background: white;
    padding: 28px;
    border-radius: 16px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.08);
    margin-bottom: 25px;
}

/* Main title */
.title {
    text-align: center;
    font-size: 34px;
    font-weight: 700;
}

/* ALL STREAMLIT BUTTONS */
div.stButton > button {
    background: linear-gradient(135deg, #4f46e5, #6366f1);
    color: white;
    border-radius: 14px;              /* rounded */
    height: 50px;
    font-weight: 600;
    border: none;
    box-shadow: 0 6px 14px rgba(79,70,229,0.35); /* shadow */
    transition: all 0.25s ease-in-out;          /* smooth animation */
}


/* HOVER EFFECT (SAFE) */
div.stButton > button:hover {
    transform: translateY(-3px);      /* lift effect */
    box-shadow: 0 10px 22px rgba(79,70,229,0.45);
}

/* Styled divider */
.section-divider {
    height: 1px;
    background: linear-gradient(to right, transparent, #c7d2fe, transparent);
    margin: 20px 0;
}
</style>
""", unsafe_allow_html=True)



# ----------------- HOME -----------------
def home():
    st.markdown("<h1 class='title'>🔐 Secure Biometric System</h1>", unsafe_allow_html=True)

    # WHITE CARD START
    st.markdown("<div class='card'>", unsafe_allow_html=True)

    # DESCRIPTION INSIDE CARD (slightly bold)
    st.markdown(
        """
        <div style="
            text-align:center;
            color:#444;
            font-size:16px;
            font-weight:600;
            margin-bottom:12px;
        ">
            This system securely verifies users using fingerprint authentication and protects sensitive data using advanced security techniques.

        </div>

        <hr style="
            border: none;
            height: 1px;
            background: linear-gradient(to right, transparent, #c7d2fe, transparent);
            margin-bottom: 25px;
        ">
        """,
        unsafe_allow_html=True
    )
    if st.session_state.user:
        col1, col2 = st.columns(2)

        with col1:
            st.success(f"✅ Logged in as: {st.session_state.user}")

        with col2:
            if st.button("🚪 Logout"):
                st.session_state.user = None
                st.session_state.page = "home"
                st.rerun()

    if st.button("📝 Register Fingerprint", use_container_width=True):
        st.session_state.page = "register"

    if st.button("🔓 Authenticate & Access Vault", use_container_width=True):
        if st.session_state.user:
            st.session_state.page = "dashboard"  # Direct access if logged in
        else:
            st.session_state.page = "login"  # Ask fingerprint if not logged in

    if st.button("📜 View System Logs", use_container_width=True):
        st.session_state.page = "logs"

    # Optional: recent logs preview
    if st.session_state.logs:
        st.markdown("<hr>", unsafe_allow_html=True)
        for log in st.session_state.logs[:3]:
            st.write("•", log)

    # WHITE CARD END
    st.markdown("</div>", unsafe_allow_html=True)


# ----------------- REGISTER -----------------
def register():
    st.markdown("<h2>📝 Fingerprint Registration</h2>", unsafe_allow_html=True)
    st.markdown("<div class='card'>", unsafe_allow_html=True)

    user_id = st.text_input("User ID")
    file = st.file_uploader("Upload Fingerprint Image", type=["png","jpg","jpeg","bmp"])
    show_templates = st.checkbox("🔍 Show templates ")

    if st.button("Register Fingerprint"):
        if user_id and file:
            img = np.array(Image.open(file))
            binary = generate_binary_template(img)

            bloom = BloomFilter(size=256, hash_count=3)
            bloom.add(binary)

            fpe = FPE(key=7)
            encrypted = fpe.encrypt(bloom.get_filter().tolist())

            os.makedirs("data", exist_ok=True)
            path = "data/templates.npy"
            data = np.load(path, allow_pickle=True).item() if os.path.exists(path) else {}

            # Check duplicate fingerprint
            duplicate_user = None

            for uid, info in data.items():
                if info["original_binary"] == binary.tolist():
                    duplicate_user = uid
                    break

            if duplicate_user:
                st.warning(f"⚠ Fingerprint already registered (User: {duplicate_user})")
                add_log(f"Duplicate fingerprint attempt for '{user_id}' (matched '{duplicate_user}')")
            else:
                data[user_id] = {
                    "original_binary": binary.tolist(),
                    "active_binary": binary.tolist(),
                    "encrypted": encrypted,
                    "version": 1
                }
                np.save(path, data)
                # ----------------- MYSQL data connection-----------------
                conn = get_db()
                cursor = conn.cursor()

                cursor.execute(
                    "INSERT INTO users (user_id, template_path, version) VALUES (%s,%s,%s)",
                    (user_id, path, 1)
                )

                conn.commit()
                conn.close()
                st.success("Fingerprint registered successfully")
                add_log(f"User '{user_id}' registered")


                if show_templates:
                    st.markdown("### 🔐 Generated Templates")
                    st.code(binary[:50])
                    st.code(bloom.get_filter()[:50])
                    st.code(encrypted[:50])


        else:
            st.error("Provide User ID and image")

    st.markdown("</div>", unsafe_allow_html=True)
    if st.button("⬅ Back"):
        st.session_state.page = "home"


# ----------------- LOGIN -----------------
def login():
    st.markdown("<h2>🔓 Fingerprint Login</h2>", unsafe_allow_html=True)
    st.markdown("<div class='card'>", unsafe_allow_html=True)


    user_id = st.text_input("User ID")
    file = st.file_uploader("Upload Fingerprint Image", type=["png","jpg","jpeg","bmp"])
    locked_user = st.session_state.get("locked_user")

    if locked_user and user_id == locked_user:
        st.warning("🔒 This account is locked due to multiple failed attempts.")
        st.info("🔄 Please complete re-authentication to continue.")

    locked_user = st.session_state.get("locked_user")

    if st.button("Login") and user_id != locked_user:

        if not os.path.exists("data/templates.npy"):
            st.error("No users registered")
            return

        data = np.load("data/templates.npy", allow_pickle=True).item()
        # ----------------- MYSQL data connection-----------------
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE user_id=%s",
            (user_id,)
        )

        result = cursor.fetchone()
        conn.close()

        if result is None:
            st.error("User not found in database")
            return

        if user_id not in data or not file:
            st.error("Invalid User ID or image")
            return

        img = np.array(Image.open(file))
        binary = generate_binary_template(img)
        stored_binary = np.array(data[user_id]["active_binary"])

        score = hamming_similarity(binary, stored_binary)

        percentage = round(score * 100, 2)

        st.info(f"🔍 Matching Score: {percentage}%")

        # Progress bar visualization
        st.write("### Matching Confidence")
        st.progress(float(score))
        st.caption(f"{percentage}% similarity with stored fingerprint")

        # -------- Matching Score Graph --------
        genuine_score = percentage
        threshold = 90
        imposter_example = 40

        labels = ["Genuine Score", "Threshold", "Impostor Example"]
        scores = [genuine_score, threshold, imposter_example]

        fig, ax = plt.subplots()
        ax.bar(labels, scores)
        ax.set_ylabel("Score (%)")
        ax.set_title("Fingerprint Matching Score Comparison")

        st.pyplot(fig)

        if user_id not in st.session_state.failures:
            st.session_state.failures[user_id] = 0

        if score >= 0.9:
            st.session_state.user = user_id
            st.session_state.failures[user_id] = 0
            st.session_state.login_success = True
            add_log(f"Login success for {user_id}")

        else:
            st.session_state.failures[user_id] += 1
            st.session_state.last_failed_user = user_id
            attempts = st.session_state.failures[user_id]

            st.error(f"❌ Authentication Failed ({attempts}/3)")
            add_log(f"Authentication failed for {user_id}")

            if attempts >= 3:
                st.error("🚨 Security Alert: Unauthorized Attempts Detected")
                add_log(f"Template revoked for {user_id}")

                # -------- Regenerate template from original fingerprint --------
                original_binary = np.array(data[user_id]["original_binary"])

                bloom = BloomFilter(size=256, hash_count=3)
                bloom.add(original_binary)

                fpe = FPE(key=7)

                data[user_id]["active_binary"] = original_binary.tolist()
                data[user_id]["encrypted"] = fpe.encrypt(bloom.get_filter().tolist())
                data[user_id]["version"] += 1

                np.save("data/templates.npy", data)

                st.session_state.locked_user = user_id
                return

    # -------- SHOW CONTINUE BUTTON AFTER SUCCESS --------
    if st.session_state.get("login_success", False):

        st.success("✅ Authentication Successful")

        if st.button("➡ Continue to Secure Vault"):
            st.session_state.login_success = False
            st.session_state.page = "dashboard"
            st.rerun()

    # ---------------- RE-AUTHENTICATION SECTION ----------------
    locked_user = st.session_state.get("locked_user")

    if locked_user and user_id == locked_user:
        st.markdown("---")
        st.markdown("## 🔄 Re-Authentication Required")

        reauth_file = st.file_uploader(
            "Upload ORIGINAL registered fingerprint",
            type=["png", "jpg", "jpeg", "bmp"],
            key="reauth_file"
        )

        if st.button("🔐 Re-Authenticate & Verify"):
            u = st.session_state.get("locked_user")

            if not u:
                st.error("No locked user found")
                return

            if not reauth_file:
                st.error("Please upload original fingerprint")
                return

            data = np.load("data/templates.npy", allow_pickle=True).item()

            img = np.array(Image.open(reauth_file))
            reauth_binary = generate_binary_template(img)

            active_binary = np.array(data[u]["active_binary"])

            score = hamming_similarity(reauth_binary, active_binary)

            percentage = round(score * 100, 2)
            st.info(f"🔍 Matching Score: {percentage}%")

            if score >= 0.9:
                st.success("✅ Access Granted – Genuine User Verified")
                add_log(f"Re-authentication success for {u}")

                # Fresh template regeneration
                bloom = BloomFilter(size=256, hash_count=3)
                bloom.add(reauth_binary)

                fpe = FPE(key=7)
                data[u]["active_binary"] = reauth_binary.tolist()
                data[u]["encrypted"] = fpe.encrypt(bloom.get_filter().tolist())
                data[u]["version"] += 1

                np.save("data/templates.npy", data)

                st.session_state.failures[u] = 0
                st.session_state.locked_user = None
                st.session_state.user = u
                st.session_state.page = "dashboard"
                st.rerun()
            else:
                st.error("❌ Access Denied – Fingerprint Mismatch")
                add_log(f"Re-authentication failed for {u}")


# ----------------- DASHBOARD -----------------
def dashboard():
    st.markdown("<h2 class='title'>🔐 Secure Data Vault</h2>", unsafe_allow_html=True)
    st.markdown("<div class='card'>", unsafe_allow_html=True)

    user = st.session_state.user
    user_vault = f"data/files/{user}"
    os.makedirs(user_vault, exist_ok=True)

    # ACTION BUTTONS

    if st.button("📤 Upload File", use_container_width=True):
        st.session_state.vault_action = "upload"

    if st.button("👁 View Files", use_container_width=True):
        st.session_state.vault_action = "view"

    if st.button("⬇ Download Files", use_container_width=True):
        st.session_state.vault_action = "download"

    if st.button("🗑 Delete File", use_container_width=True):
        st.session_state.vault_action = "delete"

    st.markdown("---")

    # UPLOAD
    if st.session_state.vault_action == "upload":
        uploaded = st.file_uploader("Select file to upload")
        if uploaded:
            with open(f"{user_vault}/{uploaded.name}", "wb") as f:
                f.write(uploaded.read())
            st.success("File uploaded successfully")
            add_log(f"File uploaded by {st.session_state.user}")

    # VIEW FILES
    if st.session_state.vault_action == "view":
        files = os.listdir(user_vault)
        if files:
            st.markdown("### 📂 Stored Files")
            for f in files:
                st.write("•", f)
        else:
            st.info("No files available")

    # DOWNLOAD FILES
    if st.session_state.vault_action == "download":
        files = os.listdir(user_vault)  # ✅ DEFINE FILES HERE

        if files:
            st.markdown("### ⬇ Download Files")
            for f in files:
                file_path = os.path.join(user_vault, f)
                with open(file_path, "rb") as file:
                    st.download_button(
                        label=f"⬇ Download {f}",
                        data=file,
                        file_name=f,
                        mime="application/octet-stream"
                    )
        else:
            st.info("No files available to download.")

    # DELETE FILES
    if st.session_state.vault_action == "delete":
        files = os.listdir(user_vault)  # ✅ define files first

        if files:
            st.markdown("### ❌ Delete Files")

            file_to_delete = st.selectbox(
                "Select file to delete",
                files,
                key="delete_file_select"
            )

            if st.button("❌ Confirm Delete"):
                file_path = os.path.join(user_vault, file_to_delete)

                if os.path.exists(file_path):
                    os.remove(file_path)
                    st.success(f"File '{file_to_delete}' deleted successfully")
                    add_log(f"File '{file_to_delete}' deleted from secure vault")
                    st.rerun()
                else:
                    st.error("File not found")
        else:
            st.info("No files to delete")

    st.markdown("</div>", unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        if st.button("⬅ Back to Home"):
            st.session_state.page = "home"
            st.rerun()

    with col2:
        if st.button("🚪 Logout"):
            st.session_state.user = None
            st.session_state.page = "home"
            st.rerun()


# ----------------- LOGS -----------------
def system_logs():
    st.markdown("<h2>📜 System Logs</h2>", unsafe_allow_html=True)

    # --------- Dynamic Statistics ---------
    total_attempts = 0
    success_count = 0
    failure_count = 0
    template_versions = {}

    # Count from logs
    for log in st.session_state.logs:
        log_lower = log.lower()
        if "login success" in log_lower:
            success_count += 1
            total_attempts += 1
        elif "authentication failed" in log_lower:
            failure_count += 1
            total_attempts += 1

    # Read template versions
    if os.path.exists("data/templates.npy"):
        data = np.load("data/templates.npy", allow_pickle=True).item()
        for user, info in data.items():
            if isinstance(info, dict):
                template_versions[user] = info.get("version", 1)
            else:
                # Old template format (list)
                template_versions[user] = 1

    # --------- Status Card ---------
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    st.markdown("### 📊 System Status (Live)")

    st.write(f"**🔢 Total Authentication Attempts:** {total_attempts}")
    st.write(f"**✅ Authentication Success:** {success_count}")
    st.write(f"**❌ Authentication Failures:** {failure_count}")

    # -------- Authentication Statistics Graph --------
    labels = ["Successful Logins", "Failed Attempts"]
    values = [success_count, failure_count]

    fig, ax = plt.subplots()
    ax.bar(labels, values)
    ax.set_ylabel("Number of Attempts")
    ax.set_title("Authentication Statistics")

    st.pyplot(fig)

    active_user = st.session_state.get("user")

    if template_versions:
        st.markdown("### 🔄 Current Template Version")

        if active_user and active_user in template_versions:
            st.write(f"- **{active_user}** → Version **{template_versions[active_user]}**")
        else:
            st.write("Login to view your template version")
    else:
        st.write("No templates available")

    st.markdown("</div>", unsafe_allow_html=True)

    # --------- Logs Timeline ---------
    if st.session_state.logs:
        st.markdown("### 🕒 Activity Timeline")
        for log in st.session_state.logs:
            st.markdown(f"<div class='card'>{log}</div>", unsafe_allow_html=True)
    else:
        st.info("No system activity recorded yet")

    if st.button("⬅ Back"):
        st.session_state.page = "home"




# ----------------- ROUTER -----------------
if st.session_state.page == "home":
    home()
elif st.session_state.page == "register":
    register()
elif st.session_state.page == "login":
    login()
elif st.session_state.page == "dashboard":
    dashboard()
elif st.session_state.page == "logs":
    system_logs()
