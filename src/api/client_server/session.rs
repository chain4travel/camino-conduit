use std::collections::HashMap;

use super::{CAMINO_PAYLOAD_LENGTH, DEVICE_ID_LENGTH, SESSION_ID_LENGTH, TOKEN_LENGTH};
use crate::{services, utils, Error, Result, Ruma};
use ruma::{
    api::client::{
        error::ErrorKind,
        session::{get_login_types, login, logout, logout_all},
        uiaa::{AuthFlow, AuthType, CaminoParams, UiaaInfo, UserIdentifier},
    },
    events::GlobalAccountDataEventType,
    push, UserId,
};
use tracing::info;

/// # `GET /_matrix/client/r0/login`
///
/// Get the supported login types of this server. One of these should be used as the `type` field
/// when logging in.
pub async fn get_login_types_route(
    _body: Ruma<get_login_types::v3::Request>,
) -> Result<get_login_types::v3::Response> {
    Ok(get_login_types::v3::Response::new(vec![
        get_login_types::v3::LoginType::Password(Default::default()),
        get_login_types::v3::LoginType::ApplicationService(Default::default()),
    ]))
}

/// # `POST /_matrix/client/r0/login`
///
/// Authenticates the user and returns an access token it can use in subsequent requests.
///
/// - The user needs to authenticate using their password (or if enabled using a json web token)
/// - If `device_id` is known: invalidates old access token of that device
/// - If `device_id` is unknown: creates a new device
/// - Returns access token that is associated with the user and device
///
/// Note: You can use [`GET /_matrix/client/r0/login`](fn.get_supported_versions_route.html) to see
/// supported login types.
pub async fn login_route(body: Ruma<login::v3::Request>) -> Result<login::v3::Response> {
    let mut uiaainfo = UiaaInfo {
        flows: vec![AuthFlow {
            stages: vec![AuthType::Camino],
        }],
        completed: Vec::new(),
        params: Default::default(),
        session: None,
        auth_error: None,
    };

    // get username from identifier
    let username = match &body.identifier {
        UserIdentifier::UserIdOrLocalpart(username) => username,
        _ => {
            return Err(Error::BadRequest(
                ErrorKind::Unrecognized,
                "Identifier type not recognized.",
            ))
        }
    };

    // get user id from username
    let user_id =
        UserId::parse_with_server_name(username.to_lowercase(), services().globals.server_name())
            .ok()
            .filter(|user_id| {
                !user_id.is_historical()
                    && user_id.server_name() == services().globals.server_name()
            })
            .ok_or(Error::BadRequest(
                ErrorKind::InvalidUsername,
                "Username is invalid.",
            ))?;

    if let Some(auth) = &body.auth {
        // Try auth
        let (worked, uiaainfo) = services()
            .uiaa
            .try_auth(&user_id, "".into(), auth, &uiaainfo)?;
        if !worked {
            return Err(Error::Uiaa(uiaainfo));
        }
    // Success!
    } else if let Some(json) = body.json_body {
        uiaainfo.params = serde_json::value::to_raw_value(&HashMap::from([(
            AuthType::Camino.as_str(),
            &CaminoParams {
                payload: utils::random_string(CAMINO_PAYLOAD_LENGTH),
            },
        )]))
        .map_err(|_| {
            Error::BadRequest(
                ErrorKind::Unknown,
                "Failed to generate payload for Camino uiaa.",
            )
        })?;
        uiaainfo.session = Some(utils::random_string(SESSION_ID_LENGTH));
        services()
            .uiaa
            .create(&user_id, "".into(), &uiaainfo, &json)?;
        return Err(Error::Uiaa(uiaainfo));
    } else {
        return Err(Error::BadRequest(ErrorKind::NotJson, "Not json."));
    }

    if !services().users.exists(&user_id)? {
        // Create user
        services().users.create(&user_id, None)?;

        // Initial account data
        services().account_data.update(
            None,
            &user_id,
            GlobalAccountDataEventType::PushRules.to_string().into(),
            &serde_json::to_value(ruma::events::push_rules::PushRulesEvent {
                content: ruma::events::push_rules::PushRulesEventContent {
                    global: push::Ruleset::server_default(&user_id),
                },
            })
            .expect("to json always works"),
        )?;
    }

    // Generate a new token for the device
    let token = utils::random_string(TOKEN_LENGTH);

    // Determine if device_id was provided and exists in the db for this user
    let device_exists = body.device_id.as_ref().map_or(false, |device_id| {
        services()
            .users
            .all_device_ids(&user_id)
            .any(|x| x.as_ref().map_or(false, |v| v == device_id))
    });

    // Generate new device id if the user didn't specify one // TODO@ check that its ok with device_exists check above
    let device_id = body
        .device_id
        .clone()
        .unwrap_or_else(|| utils::random_string(DEVICE_ID_LENGTH).into());

    if device_exists {
        services().users.set_token(&user_id, &device_id, &token)?;
    } else {
        services().users.create_device(
            &user_id,
            &device_id,
            &token,
            body.initial_device_display_name.clone(),
        )?;
    }

    info!("{} logged in", user_id);

    Ok(login::v3::Response {
        user_id,
        access_token: token,
        home_server: Some(services().globals.server_name().to_owned()),
        device_id,
        well_known: None,
        refresh_token: None,
        expires_in: None,
    })
}

/// # `POST /_matrix/client/r0/logout`
///
/// Log out the current device.
///
/// - Invalidates access token
/// - Deletes device metadata (device id, device display name, last seen ip, last seen ts)
/// - Forgets to-device events
/// - Triggers device list updates
pub async fn logout_route(body: Ruma<logout::v3::Request>) -> Result<logout::v3::Response> {
    let sender_user = body.sender_user.as_ref().expect("user is authenticated");
    let sender_device = body.sender_device.as_ref().expect("user is authenticated");

    services().users.remove_device(sender_user, sender_device)?;

    Ok(logout::v3::Response::new())
}

/// # `POST /_matrix/client/r0/logout/all`
///
/// Log out all devices of this user.
///
/// - Invalidates all access tokens
/// - Deletes all device metadata (device id, device display name, last seen ip, last seen ts)
/// - Forgets all to-device events
/// - Triggers device list updates
///
/// Note: This is equivalent to calling [`GET /_matrix/client/r0/logout`](fn.logout_route.html)
/// from each device of this user.
pub async fn logout_all_route(
    body: Ruma<logout_all::v3::Request>,
) -> Result<logout_all::v3::Response> {
    let sender_user = body.sender_user.as_ref().expect("user is authenticated");

    for device_id in services().users.all_device_ids(sender_user).flatten() {
        services().users.remove_device(sender_user, &device_id)?;
    }

    Ok(logout_all::v3::Response::new())
}
