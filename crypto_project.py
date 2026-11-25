import base64
import copy
import streamlit as st
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
PERMISSION_RISK = {
    "Camera": 15,
    "Microphone": 15,
    "Location": 20,
    "Contacts": 20,
    "Photos/Storage": 12,
    "Notifications": 5,
}

APP_PROFILES = {
    "Flashlight": {
        "purpose": "Turn the phone light on and off",
        "requested": {"Camera", "Location", "Contacts"},
        "needed": set(),
    },
    "Campus Map": {
        "purpose": "Show the user's position and provide routes",
        "requested": {"Location", "Notifications", "Contacts"},
        "needed": {"Location"},
    },
    "Voice Notes": {
        "purpose": "Record and replay voice notes",
        "requested": {"Microphone", "Photos/Storage", "Location"},
        "needed": {"Microphone", "Photos/Storage"},
    },
    "Video Caller": {
        "purpose": "Make video calls to selected contacts",
        "requested": {
            "Camera", "Microphone", "Contacts", "Notifications", "Location"
        },
        "needed": {
            "Camera", "Microphone", "Contacts", "Notifications"
        },
    },
}

st.set_page_config(
    page_title="Mobile Permission Risk Analyzer",
    page_icon="🔐",
    layout="wide",
)

st.title("📱 Mobile Permission Risk Analyzer")
st.write(
    "Review fictional app permissions, apply least privilege, "
    "and protect the analysis report with cryptography."
)
st.caption(
    "This is a classroom risk model for fictional apps. "
    "It does not scan installed phone apps or prove that an app is malware."
)


def load_profile(app_name):
    return APP_PROFILES[app_name]


def make_report(app_name, purpose, requested, needed):
    profile = {
        "purpose": purpose,
        "requested": set(requested or []),
        "needed": set(needed or []),
    }

    result = analyze_app(app_name, profile)

    report = {
        "app": result["app"],
        "purpose": result["purpose"],
        "risk_level": result["level"],
        "risk_score": result["score"],
        "requested_permissions": sorted(result["requested"]),
        "excessive_permissions": sorted(result["excessive"]),
        "least_privilege_recommendation": sorted(result["recommended"]),
    }
    return result, report


def run_attack_checks(report):
    original = protect_report(report)
    outcomes = []

    # Change one byte in the encrypted report.
    changed_ciphertext = copy.deepcopy(original)
    ciphertext = bytearray(
        base64.b64decode(changed_ciphertext["ciphertext"])
    )
    ciphertext[-1] ^= 1
    changed_ciphertext["ciphertext"] = base64.b64encode(
        ciphertext
    ).decode("ascii")

    try:
        receive_and_verify(changed_ciphertext)
        outcomes.append("❌ Tampered ciphertext was accepted")
    except InvalidTag:
        outcomes.append("✅ AES-GCM rejected the tampered ciphertext")

    # Try to unwrap the AES key with an unrelated RSA private key.
    wrong_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    try:
        wrong_private_key.decrypt(
            base64.b64decode(original["wrapped_key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        outcomes.append("❌ The wrong private key was accepted")
    except ValueError:
        outcomes.append("✅ RSA-OAEP rejected the wrong private key")

    # Change one byte in the sender's signature.
    changed_signature = copy.deepcopy(original)
    signature = bytearray(
        base64.b64decode(changed_signature["signature"])
    )
    signature[-1] ^= 1
    changed_signature["signature"] = base64.b64encode(
        signature
    ).decode("ascii")

    try:
        receive_and_verify(changed_signature)
        outcomes.append("❌ The modified signature was accepted")
    except InvalidSignature:
        outcomes.append("✅ RSA-PSS rejected the modified signature")

    return outcomes


app_name = st.selectbox(
    "Choose a fictional application",
    list(APP_PROFILES.keys()),
)

profile = load_profile(app_name)

purpose = st.text_input(
    "Stated purpose",
    value=profile["purpose"],
    key=f"purpose_{app_name}",
)

requested = st.multiselect(
    "Permissions the app requests",
    options=list(PERMISSION_RISK.keys()),
    default=[
        permission for permission in PERMISSION_RISK
        if permission in profile["requested"]
    ],
    key=f"requested_{app_name}",
)

needed = st.multiselect(
    "Permissions you judge necessary for that purpose",
    options=list(PERMISSION_RISK.keys()),
    default=[
        permission for permission in PERMISSION_RISK
        if permission in profile["needed"]
    ],
    key=f"needed_{app_name}",
)

if st.button("Analyze and protect report", type="primary"):
    result, report = make_report(
        app_name,
        purpose,
        requested,
        needed,
    )

    st.subheader("Permission risk assessment")
    st.metric("Risk level", result["level"])
    st.progress(result["score"] / 100, text=f"{result['score']} / 100")

    col1, col2 = st.columns(2)
    with col1:
        st.write("**Requested permissions**")
        st.write(sorted(result["requested"]) or "None")
        st.write("**Needed for the stated purpose**")
        st.write(sorted(result["needed"]) or "None")
        st.write("**Excessive requests**")
        st.write(sorted(result["excessive"]) or "None")

    with col2:
        st.write("**Least-privilege recommendation**")
        st.write(sorted(result["recommended"]) or "None")
        st.write(
            f"**Score:** {result['sensitivity_points']} sensitivity "
            f"+ {result['mismatch_points']} purpose-mismatch points"
        )

    # Protect the report, then have the simulated analyzer receive it.
    envelope = protect_report(report)
    received_report = receive_and_verify(envelope)

    st.subheader("Secure report transfer")
    st.success("AES-GCM decryption succeeded; RSA-PSS signature verified.")
    st.write("**Cryptography used**")
    st.write("- AES-256-GCM encrypts the report and detects ciphertext changes.")
    st.write("- RSA-OAEP protects the AES session key for the analyzer.")
    st.write("- RSA-PSS verifies the sender's digital signature.")
    st.write(f"**Analyzer received report for:** {received_report['app']}")
    st.write("**Encrypted report preview:**")
    st.code(envelope["ciphertext"][:100] + "...")

    st.subheader("Security attack demonstrations")
    for outcome in run_attack_checks(report):
        st.write(outcome)
