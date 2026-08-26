use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BindingStatus {
    DnsPending,
    CertificatePending,
    Active,
    Degraded,
    Updating,
    Removing,
    Draining,
}

impl BindingStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DnsPending => "dns_pending",
            Self::CertificatePending => "certificate_pending",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Updating => "updating",
            Self::Removing => "removing",
            Self::Draining => "draining",
        }
    }

    pub(crate) const fn is_editable(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }

    pub(crate) const fn depends_on_provider(self) -> bool {
        !matches!(self, Self::Draining)
    }
}

impl TryFrom<&str> for BindingStatus {
    type Error = InvalidStateValue;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "dns_pending" => Ok(Self::DnsPending),
            "certificate_pending" => Ok(Self::CertificatePending),
            "active" => Ok(Self::Active),
            "degraded" => Ok(Self::Degraded),
            "updating" => Ok(Self::Updating),
            "removing" => Ok(Self::Removing),
            "draining" => Ok(Self::Draining),
            _ => Err(InvalidStateValue::new("binding status", value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateStatus {
    Pending,
    Active,
}

impl CertificateStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
        }
    }
}

impl TryFrom<&str> for CertificateStatus {
    type Error = InvalidStateValue;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            _ => Err(InvalidStateValue::new("certificate status", value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BindingHealth {
    Unknown,
    Healthy,
    Unavailable,
}

impl BindingHealth {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Unavailable => "unavailable",
        }
    }
}

impl TryFrom<&str> for BindingHealth {
    type Error = InvalidStateValue;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "healthy" => Ok(Self::Healthy),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(InvalidStateValue::new("binding health", value)),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Binding {
    pub(crate) id: String,
    pub(crate) hostname: String,
    pub(crate) upstream_scheme: String,
    pub(crate) upstream_port: u16,
    pub(crate) proxied: bool,
    pub(crate) status: BindingStatus,
    pub(crate) certificate_status: CertificateStatus,
    pub(crate) health: BindingHealth,
    pub(crate) last_error: Option<String>,
    pub(crate) replace_confirmed: bool,
}

impl Binding {
    pub(crate) fn is_routable(&self) -> bool {
        self.certificate_status == CertificateStatus::Active
            && matches!(
                self.status,
                BindingStatus::Active
                    | BindingStatus::Degraded
                    | BindingStatus::Updating
                    | BindingStatus::Removing
                    | BindingStatus::Draining
            )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct PendingBindingUpdate {
    pub(crate) upstream_scheme: String,
    pub(crate) upstream_port: u16,
    pub(crate) proxied: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid {kind} value '{value}'")]
pub(crate) struct InvalidStateValue {
    kind: &'static str,
    value: String,
}

impl InvalidStateValue {
    fn new(kind: &'static str, value: &str) -> Self {
        Self {
            kind,
            value: value.to_owned(),
        }
    }
}
