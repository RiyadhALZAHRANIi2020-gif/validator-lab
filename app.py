import streamlit as st
from security.validator import ValidatorConfig, validate_command

st.set_page_config(page_title="PowerShell Security Sandbox", page_icon="🛡️")

st.title("🛡️ اختبار نظام الحماية والتحقق للأوامر")
st.write("فحص أوامر PowerShell والتأكد من توافقها مع سياسات الأمان قبل التنفيذ.")

cfg = ValidatorConfig(allowed_hosts=frozenset({"TEST-DC", "TEST-CLIENT"}))

tool = st.selectbox(
    "اختر الأداة (Tool):",
    ["run_readonly_check", "run_change_command", "verify_on_client"]
)

host = st.text_input("المضيف المستهدف (Target Host):", value="TEST-DC")

command = st.text_area(
    "أدخل أمر PowerShell:",
    value="Get-GPO -All",
)

if st.button("فحص الأمر (Validate)"):
    result = validate_command(tool, command, host, cfg)
    
    st.markdown("---")
    st.subheader("نتيجة الفحص:")
    
    if result.allowed:
        st.success("✅ مسموح بتنفيذ الأمر!")
        st.markdown("**الأمر المعياري الآمن (Normalized):**")
        st.code(result.normalized, language="powershell")
        
        if result.requires_approval:
            st.warning("⚠️ تنبيه: هذا الأمر يتطلب موافقة بشرية مسبقة قبل التنفيذ.")
    else:
        st.error("❌ تم رفض الأمر!")
        st.markdown(f"**السبب:** `{result.reason}`")
