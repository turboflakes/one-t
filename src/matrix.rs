// The MIT License (MIT)
// Copyright © 2021 Aukbit Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
#![allow(dead_code)]
use crate::config::CONFIG;
use crate::errors::MatrixError;
use crate::onet::{ReportType, EPOCH_FILENAME};
use crate::runtimes::support::SupportedRuntime;
use async_recursion::async_recursion;
use base64::encode;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    result::Result,
    str::FromStr,
    thread, time,
};
use subxt::sp_runtime::AccountId32;
use url::form_urlencoded::byte_serialize;
const MATRIX_URL: &str = "https://matrix.org/_matrix/client/r0";
const MATRIX_MEDIA_URL: &str = "https://matrix.org/_matrix/media/r0";
const MATRIX_BOT_NAME: &str = "ONE-T";
const MATRIX_NEXT_BATCH_FILENAME: &str = ".next_batch";
pub const MATRIX_SUBSCRIBERS_FILENAME: &str = ".subscribers";

type AccessToken = String;
type SyncToken = String;
type RoomID = String;
type EventID = String;
type Stash = String;
type URI = String;
pub type UserID = String;

impl SupportedRuntime {
    fn public_room_alias(&self) -> String {
        let config = CONFIG.clone();
        format!("#{}", config.matrix_public_room)
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
enum Commands {
    Help,
    Legends,
    Subscribe(ReportType, UserID, Option<Stash>),
    Unsubscribe(ReportType, UserID, Option<Stash>),
    NotSupported,
}

#[derive(Deserialize, Debug, Default)]
struct Room {
    #[serde(default)]
    room_id: RoomID,
    #[serde(default)]
    servers: Vec<String>,
    #[serde(default)]
    room_alias: String,
    #[serde(default)]
    room_alias_name: String,
}

fn define_private_room_alias_name(
    pkg_name: &str,
    chain_name: &str,
    matrix_user: &str,
    matrix_bot_user: &str,
) -> String {
    encode(
        format!(
            "{}/{}/{}/{}",
            pkg_name, chain_name, matrix_user, matrix_bot_user
        )
        .as_bytes(),
    )
}

impl Room {
    fn new_private(chain: SupportedRuntime, user_id: &str) -> Room {
        let config = CONFIG.clone();
        let room_alias_name = define_private_room_alias_name(
            env!("CARGO_PKG_NAME"),
            &chain.to_string(),
            &user_id,
            &config.matrix_bot_user,
        );
        let v: Vec<&str> = config.matrix_bot_user.split(":").collect();
        Room {
            room_alias_name: room_alias_name.to_string(),
            room_alias: format!("#{}:{}", room_alias_name.to_string(), v.last().unwrap()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    r#type: String,
    user: String,
    password: String,
}

#[derive(Deserialize, Debug)]
struct LoginResponse {
    user_id: String,
    access_token: AccessToken,
    home_server: String,
    device_id: String,
    // "well_known": {
    //   "m.homeserver": {
    //       "base_url": "https://matrix-client.matrix.org/"
    //   }
    // }
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateRoomRequest {
    name: String,
    room_alias_name: String,
    topic: String,
    preset: String,
    invite: Vec<String>,
    is_direct: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct SendRoomMessageRequest {
    msgtype: String,
    body: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    format: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    formatted_body: String,
    #[serde(skip_serializing_if = "FileInfo::is_empty")]
    info: FileInfo,
    #[serde(skip_serializing_if = "String::is_empty")]
    url: String,
}

impl SendRoomMessageRequest {
    pub fn with_message(message: &str, formatted_message: Option<&str>) -> Self {
        if let Some(formatted_msg) = formatted_message {
            Self {
                msgtype: "m.text".to_string(),
                body: message.to_string(),
                format: "org.matrix.custom.html".to_string(),
                formatted_body: formatted_msg.to_string(),
                ..Default::default()
            }
        } else {
            Self {
                msgtype: "m.text".to_string(),
                body: message.to_string(),
                ..Default::default()
            }
        }
    }

    pub fn with_attachment(filename: &str, url: &str, file_info: Option<FileInfo>) -> Self {
        if let Some(info) = file_info {
            Self {
                msgtype: "m.file".to_string(),
                body: filename.to_string(),
                url: url.to_string(),
                info: FileInfo {
                    mimetype: info.mimetype,
                    size: info.size,
                },
                ..Default::default()
            }
        } else {
            Self {
                msgtype: "m.file".to_string(),
                body: filename.to_string(),
                url: url.to_string(),
                ..Default::default()
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FileInfo {
    mimetype: String,
    size: u64,
}

impl FileInfo {
    pub fn with_size(size: u64) -> Self {
        Self {
            mimetype: "text/plain".to_string(),
            size,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.mimetype.is_empty() && self.size == 0
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RoomEventFilter {
    types: Vec<String>,
    rooms: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct RoomEventsResponse {
    chunk: Vec<ClientEvent>,
    start: SyncToken,
    end: SyncToken,
}

#[derive(Deserialize, Debug)]
struct ClientEvent {
    content: EventContent,
    origin_server_ts: u64,
    room_id: String,
    sender: String,
    r#type: String,
    // unsigned
    event_id: String,
    user_id: String,
    #[serde(skip)]
    age: u32,
}

#[derive(Deserialize, Debug)]
struct EventContent {
    body: String,
    msgtype: String,
}

#[derive(Deserialize, Debug)]
struct SendRoomMessageResponse {
    event_id: EventID,
}

#[derive(Deserialize, Debug)]
struct JoinedRoomsResponse {
    joined_rooms: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct SyncResponse {
    next_batch: String,
}

#[derive(Deserialize, Debug)]
struct UploadResponse {
    content_uri: String,
}

#[derive(Deserialize, Debug)]
struct ErrorResponse {
    errcode: String,
    error: String,
}

#[derive(Clone, Debug)]
pub struct Matrix {
    pub client: reqwest::Client,
    access_token: Option<String>,
    chain: SupportedRuntime,
    public_room_id: String,
    callout_public_room_ids: Vec<String>,
    disabled: bool,
}

impl Default for Matrix {
    fn default() -> Matrix {
        Matrix {
            client: reqwest::Client::new(),
            access_token: None,
            chain: SupportedRuntime::Kusama,
            public_room_id: String::from(""),
            callout_public_room_ids: Vec::new(),
            disabled: false,
        }
    }
}

impl Matrix {
    pub fn new() -> Matrix {
        let config = CONFIG.clone();
        Matrix {
            disabled: config.matrix_disabled,
            ..Default::default()
        }
    }

    pub async fn login(&mut self) -> Result<(), MatrixError> {
        if self.disabled {
            return Ok(());
        }
        let config = CONFIG.clone();
        if let None = config.matrix_bot_user.find(":") {
            return Err(MatrixError::Other(format!("matrix bot user '{}' does not specify the matrix server e.g. '@your-own-bot-account:matrix.org'", config.matrix_bot_user)));
        }
        let client = self.client.clone();
        let req = LoginRequest {
            r#type: "m.login.password".to_string(),
            user: config.matrix_bot_user.to_string(),
            password: config.matrix_bot_password.to_string(),
        };

        let res = client
            .post(format!("{}/login", MATRIX_URL))
            .json(&req)
            .send()
            .await?;

        debug!("response {:?}", res);
        match res.status() {
            reqwest::StatusCode::OK => {
                let response = res.json::<LoginResponse>().await?;
                self.access_token = Some(response.access_token);
                info!(
                    "The '{} Bot' user {} has been authenticated at {}",
                    MATRIX_BOT_NAME, response.user_id, response.home_server
                );
                Ok(())
            }
            _ => {
                let response = res.json::<ErrorResponse>().await?;
                Err(MatrixError::Other(response.error))
            }
        }
    }

    #[allow(dead_code)]
    pub async fn logout(&mut self) -> Result<(), MatrixError> {
        if self.disabled {
            return Ok(());
        }
        match &self.access_token {
            Some(access_token) => {
                let client = self.client.clone();
                let res = client
                    .post(format!(
                        "{}/logout?access_token={}",
                        MATRIX_URL, access_token
                    ))
                    .send()
                    .await?;
                debug!("response {:?}", res);
                match res.status() {
                    reqwest::StatusCode::OK => {
                        self.access_token = None;
                        Ok(())
                    }
                    _ => {
                        let response = res.json::<ErrorResponse>().await?;
                        Err(MatrixError::Other(response.error))
                    }
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    // Login user and join public room
    pub async fn authenticate(&mut self, chain: SupportedRuntime) -> Result<(), MatrixError> {
        if self.disabled {
            return Ok(());
        }
        let config = CONFIG.clone();
        // Set chain
        self.chain = chain;
        // Login
        self.login().await?;
        // Verify if user did not disabled public room in config
        if !config.matrix_public_room_disabled {
            // Join public room if not a member
            match self
                .get_room_id_by_room_alias(&self.chain.public_room_alias())
                .await?
            {
                Some(public_room_id) => {
                    // Join room if not already a member
                    let joined_rooms = self.get_joined_rooms().await?;
                    debug!("joined_rooms {:?}", joined_rooms);
                    if !joined_rooms.contains(&public_room_id) {
                        self.join_room(&public_room_id).await?;
                    }
                    self.public_room_id = public_room_id;
                    info!(
                        "Messages will be sent to room {} (Public)",
                        self.chain.public_room_alias()
                    );
                }
                None => {
                    return Err(MatrixError::Other(format!(
                        "Public room {} not found.",
                        self.chain.public_room_alias()
                    )))
                }
            }
            // Callout public rooms
            for r in config.matrix_callout_public_rooms.iter() {
                // Join public room if not a member
                let public_room = format!("#{}", r);
                match self.get_room_id_by_room_alias(&public_room).await? {
                    Some(public_room_id) => {
                        // Join room if not already a member
                        let joined_rooms = self.get_joined_rooms().await?;
                        debug!("joined_rooms {:?}", joined_rooms);
                        if !joined_rooms.contains(&public_room_id) {
                            self.join_room(&public_room_id).await?;
                        }
                        self.callout_public_room_ids.push(public_room_id);
                        info!(
                            "Callout messages will be sent to room {} (Public)",
                            public_room
                        );
                    }
                    None => {
                        return Err(MatrixError::Other(format!(
                            "Public room {} not found.",
                            public_room
                        )))
                    }
                }
            }
            // Callout public room ids
            for public_room_id in config.matrix_callout_public_room_ids.iter() {
                // Join room if not already a member
                let joined_rooms = self.get_joined_rooms().await?;
                debug!("joined_rooms {:?}", joined_rooms);
                if !joined_rooms.contains(&public_room_id) {
                    self.join_room(&public_room_id).await?;
                }
                self.callout_public_room_ids
                    .push(public_room_id.to_string());
                info!(
                    "Callout messages will be sent to room {} (Public)",
                    public_room_id
                );
            }
        }
        Ok(())
    }

    pub async fn lazy_load_and_process_commands(&self) -> Result<(), MatrixError> {
        let config = CONFIG.clone();
        let subscribers_filename = format!("{}{}", config.data_path, MATRIX_SUBSCRIBERS_FILENAME);
        let next_batch_filename = format!("{}{}", config.data_path, MATRIX_NEXT_BATCH_FILENAME);
        let epoch_filename = format!("{}{}", config.data_path, EPOCH_FILENAME);
        while let Some(token) = self.get_next_or_sync().await? {
            if let Some((commands, _, next_token)) =
                self.get_commands_from_public_room(&token).await?
            {
                for cmd in commands.iter() {
                    match cmd {
                        Commands::Help => self.reply_help().await?,
                        Commands::Legends => self.reply_legends().await?,
                        Commands::Subscribe(report, who, stash) => {
                            match report {
                                ReportType::Validator => {
                                    if let Some(stash) = stash {
                                        // Verify stash
                                        if let Ok(_) = AccountId32::from_str(&stash) {
                                            // Write stash,user in subscribers file if doesn't already exist
                                            let subscriber = format!("{stash},{who}\n");
                                            if Path::new(&subscribers_filename).exists() {
                                                let subscribers =
                                                    fs::read_to_string(&subscribers_filename)?;
                                                let mut x = 0;
                                                for _ in subscribers.lines() {
                                                    x += 1;
                                                }
                                                if x == config.maximum_subscribers {
                                                    let message = format!("⛔ The maximum number of subscribers have been reached → {}", config.maximum_subscribers);
                                                    self.send_public_message(&message, None)
                                                        .await?;
                                                    continue;
                                                }

                                                if !subscribers.contains(&subscriber) {
                                                    let mut file = OpenOptions::new()
                                                        .append(true)
                                                        .open(&subscribers_filename)?;
                                                    file.write_all(subscriber.as_bytes())?;
                                                    let message = format!("📥 New subscription! <i>{}</i> subscribed for {stash}", report.name());
                                                    self.send_private_message(
                                                        who,
                                                        &message,
                                                        Some(&message),
                                                    )
                                                    .await?;
                                                } else {
                                                    let message = format!("👍 It's here! {stash} is already subscribed. The report should be sent soon.");
                                                    self.send_private_message(
                                                        who,
                                                        &message,
                                                        Some(&message),
                                                    )
                                                    .await?;
                                                }
                                            } else {
                                                fs::write(&subscribers_filename, subscriber)?;
                                                let message = format!("📥 New subscription! <i>{}</i> subscribed for {stash}", report.name());
                                                self.send_private_message(
                                                    who,
                                                    &message,
                                                    Some(&message),
                                                )
                                                .await?;
                                            }
                                        } else {
                                            let message = format!(
                                                "{who} try again! {stash} is an invalid address."
                                            );
                                            self.send_public_message(&message, None).await?;
                                        }
                                    }
                                }
                                ReportType::Ranking => {
                                    // Write user in subscribers.ranking file if doesn't already exist
                                    let subscriber = format!("{who}\n");
                                    let path = format!(
                                        "{}.{}",
                                        subscribers_filename,
                                        report.to_string().to_lowercase()
                                    );
                                    if Path::new(&path).exists() {
                                        let subscribers = fs::read_to_string(&path)?;
                                        let mut x = 0;
                                        for _ in subscribers.lines() {
                                            x += 1;
                                        }
                                        if x == config.maximum_subscribers {
                                            let message = format!("⛔ The maximum number of subscribers have been reached → {}", config.maximum_subscribers);
                                            self.send_public_message(&message, None).await?;
                                            continue;
                                        }

                                        if !subscribers.contains(&subscriber) {
                                            let mut file =
                                                OpenOptions::new().append(true).open(&path)?;
                                            file.write_all(subscriber.as_bytes())?;
                                            let message = format!(
                                                "📥 New subscription! <i>{}</i> subscribed.",
                                                report.name()
                                            );
                                            self.send_private_message(
                                                who,
                                                &message,
                                                Some(&message),
                                            )
                                            .await?;
                                        } else {
                                            let message = format!("👍 It's here! <i>{}</i> is already subscribed. The report should be sent soon.", report.name());
                                            self.send_private_message(
                                                who,
                                                &message,
                                                Some(&message),
                                            )
                                            .await?;
                                        }
                                    } else {
                                        fs::write(&path, subscriber)?;
                                        let message = format!(
                                            "📥 New subscription! <i>{}</i> subscribed.",
                                            report.name()
                                        );
                                        self.send_private_message(who, &message, Some(&message))
                                            .await?;
                                    }
                                }
                                _ => {
                                    // ReportType::Groups
                                    // ReportType::Parachains
                                    // Read current epoch from cached file
                                    let current_epoch = fs::read_to_string(&epoch_filename)?;
                                    let current_epoch: u32 = current_epoch.parse().unwrap_or(0);
                                    for e in 0..config.maximum_reports {
                                        let subscriber = format!("{who}\n");
                                        let epoch = current_epoch + e;
                                        let path = format!(
                                            "{}.{}.{}",
                                            subscribers_filename,
                                            report.to_string().to_lowercase(),
                                            epoch
                                        );
                                        if Path::new(&path).exists() {
                                            let subscribers = fs::read_to_string(&path)?;
                                            let mut x = 0;
                                            for _ in subscribers.lines() {
                                                x += 1;
                                            }
                                            if x == config.maximum_subscribers {
                                                let message = format!("⛔ The maximum number of subscribers have been reached → {}", config.maximum_subscribers);
                                                self.send_public_message(&message, None).await?;
                                                break;
                                            }
                                            if !subscribers.contains(&subscriber) {
                                                let mut file =
                                                    OpenOptions::new().append(true).open(&path)?;
                                                file.write_all(subscriber.as_bytes())?;
                                                let message = format!(
                                                    "📥 <i>{}</i> subscribed for epoch {}.",
                                                    report.name(),
                                                    epoch
                                                );
                                                self.send_private_message(
                                                    who,
                                                    &message,
                                                    Some(&message),
                                                )
                                                .await?;
                                            } else {
                                                let message = format!("👍 <i>{}</i> for epoch {} is already subscribed.", report.name(), epoch);
                                                self.send_private_message(
                                                    who,
                                                    &message,
                                                    Some(&message),
                                                )
                                                .await?;
                                            }
                                        } else {
                                            fs::write(&path, subscriber)?;
                                            let message = format!(
                                                "📥 <i>{}</i> subscribed for epoch {}.",
                                                report.name(),
                                                epoch
                                            );
                                            self.send_private_message(
                                                who,
                                                &message,
                                                Some(&message),
                                            )
                                            .await?;
                                        }
                                    }
                                }
                            }
                        }
                        Commands::Unsubscribe(report, who, stash) => {
                            match report {
                                ReportType::Validator => {
                                    if let Some(stash) = stash {
                                        // Remove stash,user from subscribers file
                                        let subscriber = format!("{stash},{who}\n");
                                        let path = format!(
                                            "{}{}",
                                            config.data_path, MATRIX_SUBSCRIBERS_FILENAME
                                        );
                                        if Path::new(&path).exists() {
                                            let subscribers = fs::read_to_string(&path)?;
                                            if subscribers.contains(&subscriber) {
                                                fs::write(
                                                    &path,
                                                    subscribers.replace(&subscriber, ""),
                                                )?;
                                                let message = format!(
                                                    "🗑️ <i>{}</i> unsubscribed for {stash}",
                                                    report.name()
                                                );
                                                self.send_private_message(who, &message, Some(&message))
                                                    .await?;
                                            }
                                        }
                                    }
                                }
                                ReportType::Ranking => {
                                    // Remove user from subscribers file
                                    let subscriber = format!("{who}\n");
                                    let path = format!(
                                        "{}.{}",
                                        subscribers_filename,
                                        report.to_string().to_lowercase()
                                    );
                                    if Path::new(&path).exists() {
                                        let subscribers = fs::read_to_string(&path)?;
                                        if subscribers.contains(&subscriber) {
                                            fs::write(&path, subscribers.replace(&subscriber, ""))?;
                                            let message =
                                                format!("🗑️ <i>{}</i> unsubscribed.", report.name());
                                            self.send_private_message(
                                                who,
                                                &message,
                                                Some(&message),
                                            )
                                            .await?;
                                        }
                                    }
                                }
                                _ => (),
                            }
                        }
                        _ => (),
                    }
                }
                // Cache next token
                fs::write(&next_batch_filename, next_token)?;
            }
            thread::sleep(time::Duration::from_secs(6));
        }
        Ok(())
    }

    async fn get_room_id_by_room_alias(
        &self,
        room_alias: &str,
    ) -> Result<Option<RoomID>, MatrixError> {
        let client = self.client.clone();
        let room_alias_encoded: String = byte_serialize(room_alias.as_bytes()).collect();
        let res = client
            .get(format!(
                "{}/directory/room/{}",
                MATRIX_URL, room_alias_encoded
            ))
            .send()
            .await?;
        debug!("response {:?}", res);
        match res.status() {
            reqwest::StatusCode::OK => {
                let room = res.json::<Room>().await?;
                debug!("{} * Matrix room alias", room_alias);
                Ok(Some(room.room_id))
            }
            reqwest::StatusCode::NOT_FOUND => Ok(None),
            _ => {
                let response = res.json::<ErrorResponse>().await?;
                Err(MatrixError::Other(response.error))
            }
        }
    }

    async fn create_private_room(&self, user_id: &str) -> Result<Option<Room>, MatrixError> {
        match &self.access_token {
            Some(access_token) => {
                let client = self.client.clone();
                let room: Room = Room::new_private(self.chain, user_id);
                let req = CreateRoomRequest {
                    name: format!("{} {} Bot (Private)", self.chain, MATRIX_BOT_NAME),
                    room_alias_name: room.room_alias_name.to_string(),
                    topic: format!("{} Bot <> Performance report bot for the {} network with a focus on the One Thousand validator programme", MATRIX_BOT_NAME, self.chain),
                    preset: "trusted_private_chat".to_string(),
                    invite: vec![user_id.to_string()],
                    is_direct: true,
                };
                let res = client
                    .post(format!(
                        "{}/createRoom?access_token={}",
                        MATRIX_URL, access_token
                    ))
                    .json(&req)
                    .send()
                    .await?;

                debug!("response {:?}", res);
                match res.status() {
                    reqwest::StatusCode::OK => {
                        let mut r = res.json::<Room>().await?;
                        r.room_alias = room.room_alias;
                        r.room_alias_name = room.room_alias_name;
                        info!("{} * Matrix private room alias created", r.room_alias);
                        Ok(Some(r))
                    }
                    _ => {
                        let response = res.json::<ErrorResponse>().await?;
                        Err(MatrixError::Other(response.error))
                    }
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    async fn get_or_create_private_room(&self, user_id: &str) -> Result<Option<Room>, MatrixError> {
        match &self.access_token {
            Some(_) => {
                let mut room: Room = Room::new_private(self.chain, user_id);
                match self.get_room_id_by_room_alias(&room.room_alias).await? {
                    Some(room_id) => {
                        room.room_id = room_id;
                        Ok(Some(room))
                    }
                    None => Ok(self.create_private_room(user_id).await?),
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    async fn get_joined_rooms(&self) -> Result<Vec<String>, MatrixError> {
        match &self.access_token {
            Some(access_token) => {
                let client = self.client.clone();
                let res = client
                    .get(format!(
                        "{}/joined_rooms?access_token={}",
                        MATRIX_URL, access_token
                    ))
                    .send()
                    .await?;
                debug!("response {:?}", res);
                match res.status() {
                    reqwest::StatusCode::OK => {
                        let response = res.json::<JoinedRoomsResponse>().await?;
                        Ok(response.joined_rooms)
                    }
                    _ => {
                        let response = res.json::<ErrorResponse>().await?;
                        Err(MatrixError::Other(response.error))
                    }
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    // Upload file
    // https://matrix.org/docs/spec/client_server/r0.6.0#m-file
    pub fn upload_file(&self, filename: &str) -> Result<Option<URI>, MatrixError> {
        match &self.access_token {
            Some(access_token) => {
                let file = File::open(filename)?;
                let client = reqwest::blocking::Client::new();
                let res = client
                    .post(format!(
                        "{}/upload?access_token={}",
                        MATRIX_MEDIA_URL, access_token
                    ))
                    .body(file)
                    .send()?;
                match res.status() {
                    reqwest::StatusCode::OK => {
                        let response = res.json::<UploadResponse>()?;
                        Ok(Some(response.content_uri))
                    }
                    _ => {
                        let response = res.json::<ErrorResponse>()?;
                        Err(MatrixError::Other(response.error))
                    }
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    // Sync
    // https://spec.matrix.org/v1.2/client-server-api/#syncing
    async fn get_next_or_sync(&self) -> Result<Option<SyncToken>, MatrixError> {
        let config = CONFIG.clone();
        let next_batch_filename = format!("{}{}", config.data_path, MATRIX_NEXT_BATCH_FILENAME);
        // Try to read first cached token from file
        match fs::read_to_string(&next_batch_filename) {
            Ok(token) => Ok(Some(token)),
            _ => {
                match &self.access_token {
                    Some(access_token) => {
                        let client = self.client.clone();
                        let res = client
                            .get(format!("{}/sync?access_token={}", MATRIX_URL, access_token))
                            .send()
                            .await?;
                        match res.status() {
                            reqwest::StatusCode::OK => {
                                let response = res.json::<SyncResponse>().await?;
                                // Persist token to file in case we need to restore commands from previously attempt
                                fs::write(&next_batch_filename, &response.next_batch)
                                    .expect("Unable to write .matrix.next_batch file");
                                Ok(Some(response.next_batch))
                            }
                            _ => {
                                let response = res.json::<ErrorResponse>().await?;
                                Err(MatrixError::Other(response.error))
                            }
                        }
                    }
                    None => Err(MatrixError::Other("access_token not defined".to_string())),
                }
            }
        }
    }

    // Getting events for a room
    // https://spec.matrix.org/v1.2/client-server-api/#get_matrixclientv3roomsroomidmessages
    async fn get_commands_from_public_room(
        &self,
        from_token: &str,
    ) -> Result<Option<(Vec<Commands>, SyncToken, SyncToken)>, MatrixError> {
        match &self.access_token {
            Some(access_token) => {
                let client = self.client.clone();
                let room_id_encoded: String =
                    byte_serialize(self.public_room_id.as_bytes()).collect();
                let filter = RoomEventFilter {
                    types: vec!["m.room.message".to_string()],
                    rooms: vec![self.public_room_id.to_string()],
                };
                let filter_str = serde_json::to_string(&filter)?;
                let filter_encoded: String = byte_serialize(filter_str.as_bytes()).collect();
                let res = client
                    .get(format!(
                        "{}/rooms/{}/messages?access_token={}&from={}&filter={}",
                        MATRIX_URL, room_id_encoded, access_token, from_token, filter_encoded
                    ))
                    .send()
                    .await?;
                match res.status() {
                    reqwest::StatusCode::OK => {
                        let events = res.json::<RoomEventsResponse>().await?;
                        let mut commands: Vec<Commands> = Vec::new();
                        // Parse message to commands
                        for message in events.chunk.iter() {
                            if message.content.msgtype == "m.text" {
                                match message.content.body.split_once(' ') {
                                    None => {
                                        if message.content.body == "!help" {
                                            commands.push(Commands::Help);
                                        } else if message.content.body == "!legends" {
                                            commands.push(Commands::Legends);
                                        }
                                    }
                                    Some((cmd, value)) => match cmd {
                                        "!subscribe" => match value {
                                            "groups" => commands.push(Commands::Subscribe(
                                                ReportType::Groups,
                                                message.sender.to_string(),
                                                None,
                                            )),
                                            "parachains" => commands.push(Commands::Subscribe(
                                                ReportType::Parachains,
                                                message.sender.to_string(),
                                                None,
                                            )),
                                            "ranking" => commands.push(Commands::Subscribe(
                                                ReportType::Ranking,
                                                message.sender.to_string(),
                                                None,
                                            )),
                                            stash => commands.push(Commands::Subscribe(
                                                ReportType::Validator,
                                                message.sender.to_string(),
                                                Some(stash.to_string()),
                                            )),
                                        },
                                        "!unsubscribe" => match value {
                                            "ranking" => commands.push(Commands::Unsubscribe(
                                                ReportType::Ranking,
                                                message.sender.to_string(),
                                                None,
                                            )),
                                            stash => commands.push(Commands::Unsubscribe(
                                                ReportType::Validator,
                                                message.sender.to_string(),
                                                Some(stash.to_string()),
                                            )),
                                        },
                                        _ => commands.push(Commands::NotSupported),
                                    },
                                };
                            }
                        }
                        Ok(Some((commands, events.start, events.end)))
                    }
                    _ => {
                        let response = res.json::<ErrorResponse>().await?;
                        Err(MatrixError::Other(response.error))
                    }
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    #[async_recursion]
    async fn join_room(&self, room_id: &str) -> Result<Option<RoomID>, MatrixError> {
        match &self.access_token {
            Some(access_token) => {
                let client = self.client.clone();
                let room_id_encoded: String = byte_serialize(room_id.as_bytes()).collect();
                let res = client
                    .post(format!(
                        "{}/join/{}?access_token={}",
                        MATRIX_URL, room_id_encoded, access_token
                    ))
                    .send()
                    .await?;
                debug!("response {:?}", res);
                match res.status() {
                    reqwest::StatusCode::OK => {
                        let room = res.json::<Room>().await?;
                        info!("The room {} has been joined.", room.room_id);
                        Ok(Some(room.room_id))
                    }
                    reqwest::StatusCode::TOO_MANY_REQUESTS => {
                        let response = res.json::<ErrorResponse>().await?;
                        warn!("Matrix {} -> Wait 5 seconds and try again", response.error);
                        thread::sleep(time::Duration::from_secs(5));
                        return self.join_room(room_id).await;
                    }
                    _ => {
                        let response = res.json::<ErrorResponse>().await?;
                        Err(MatrixError::Other(response.error))
                    }
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    pub async fn reply_help(&self) -> Result<(), MatrixError> {
        let config = CONFIG.clone();
        let mut message = String::from("✨ Supported commands:<br>");
        message.push_str("<b>!subscribe <i>STASH_ADDRESS</i></b> - Subscribe to the <i>Validator Performance Report</i> for the stash address specified. The report is sent via DM at the end of each session until unsubscribed. The report is only sent if the <i>para-validator</i> role was assigned to the validator on the previous session.<br>");
        message.push_str(
            "<b>!unsubscribe <i>STASH_ADDRESS</i></b> - Unsubscribe the stash address from the <i>Validator Performance Report</i> subscribers list.<br>",
        );
        message.push_str(&format!("<b>!subscribe groups</b> - Subscribe to the <i>Validator Groups Performance Report</i>. The report is sent via DM at the end of the next {} sessions.<br>", config.maximum_reports));
        message.push_str(&format!("<b>!subscribe parachains</b> - Subscribe to the <i>Parachains Performance Report</i>. The report is sent via DM at the end of the next {} sessions.<br>", config.maximum_reports));
        message.push_str("<b>!subscribe ranking</b> - Subscribe to the <i>ONE-T Performance Ranking Report</i>. The report is a Tab-delimited gzip compressed file, sent via DM at the end of each era until unsubscribed.<br>");
        message.push_str(
            "<b>!unsubscribe ranking</b> - Unsubscribe to the <i>ONE-T Performance Ranking Report</i> subscribers list.<br>",
        );
        // message.push_str("!report - Send validator \\<Stash Address\\> performance report for the current epoch.<br>");
        message.push_str("<b>!legends</b> - Print legends of all reports.<br>");
        message.push_str("<b>!help</b> - Print this message.<br>");
        message.push_str("——<br>");
        message.push_str(&format!(
            "<code>{} v{}</code><br>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));

        return self.send_public_message(&message, Some(&message)).await;
    }

    pub async fn reply_legends(&self) -> Result<(), MatrixError> {
        let mut message = String::from(
            "💡 Stats are collected between the interval of blocks specified in each report.<br>",
        );
        message.push_str("<br>");
        message.push_str("<i>Val. performance report legend:</i><br>");
        message.push_str("→: !subscribe STASH_ADDRESS<br>");
        message.push_str("↻: Total number of core assignments (parachains) by the validator.<br>");
        message.push_str("❒: Total number of authored blocks by the validator.<br>");
        message.push_str("✓i: Total number of implicit votes by the validator.<br>");
        message.push_str("✓e: Total number of explicit votes by the validator.<br>");
        message.push_str("✗: Total number of missed votes by the validator.<br>");
        message.push_str("GRD: Grade reflects Total Votes Ratio (TVR). TVR = (✓i + ✓e) / (✓i + ✓e + ✗)). Grade system: A+ >= 90% ; A >= 80% ; B+ >= 70% ; B >= 60% ; C+ >= 55% ; C >= 50% ; D+ >= 45% ; D >= 40% ; F < 40%).<br>");
        message.push_str("MVR: Missed Votes Ratio.<br>");
        message.push_str("PPTS: Sum of para-validator points the validator earned.<br>");
        message.push_str(
            "TPTS: Sum of para-validator points + authored blocks points the validator earned.<br>",
        );
        message.push_str("*: ✓ is the Total number of (implicit + explicit) votes and ✗ is the Total number of missed votes by the subscribed validator while assigned to the parachain.<br>");
        message.push_str("A, B, C, D: Represents each validator in the same val. group as the subscribed validator, while assigned to the parachain.<br>");
        message.push_str("<br>");
        message.push_str("<i>Val. groups performance report legend:</i><br>");
        message.push_str("→: !subscribe groups<br>");
        message.push_str("↻: Total number of core assignements.<br>");
        message.push_str("❒: Total number of authored blocks.<br>");
        message.push_str("✓i: Total number of implicit votes.<br>");
        message.push_str("✓e: Total number of explicit votes.<br>");
        message.push_str("✗: Total number of missed votes by the validator.<br>");
        message.push_str("GRD: Grade reflects Total Votes Ratio.<br>");
        message.push_str("MVR: Missed Votes Ratio.<br>");
        message.push_str("PPTS: Sum of para-validator points the validator earned.<br>");
        message.push_str(
            "TPTS: Sum of para-validator points + authored blocks points the validator earned.<br>",
        );
        message
            .push_str("NOTE: Val. groups and validators are sorted by para-validator points in descending order.<br>");
        message.push_str("<br>");
        message.push_str("<i>Parachains performance report legend:</i><br>");
        message.push_str("→: !subscribe parachains<br>");
        message.push_str("↻: Total number of validator group rotations per parachain.<br>");
        message.push_str("❒: Total number of authored blocks from all validators when assigned to the parachain.<br>");
        message.push_str("✓i: Total number of implicit votes from all validators when assigned to the parachain.<br>");
        message.push_str("✓e: Total number of explicit votes from all validators when assigned to the parachain.<br>");
        message.push_str("✗: Total number of missed votes from all validators when assigned to the parachain.<br>");
        message.push_str("PPTS: Sum of para-validator points from all validators.<br>");
        message.push_str(
            "TPTS: Sum of para-validator points + authored blocks points from all validators.<br>",
        );
        message.push_str(
            "NOTE: Parachains are sorted by para-validator points in descending order.<br>",
        );
        message.push_str("<br>");

        return self.send_public_message(&message, Some(&message)).await;
    }

    pub async fn send_private_message(
        &self,
        to_user_id: &str,
        message: &str,
        formatted_message: Option<&str>,
    ) -> Result<(), MatrixError> {
        if self.disabled {
            return Ok(());
        }
        // Get or create user private room
        if let Some(private_room) = self.get_or_create_private_room(to_user_id).await? {
            // Send message to the private room (bot <=> user)
            let req = SendRoomMessageRequest::with_message(&message, formatted_message);
            self.dispatch_message(&private_room.room_id, &req).await?;
        }

        Ok(())
    }

    pub async fn send_public_message(
        &self,
        message: &str,
        formatted_message: Option<&str>,
    ) -> Result<(), MatrixError> {
        if self.disabled {
            return Ok(());
        }
        let config = CONFIG.clone();
        // Send message to public room (public room available for the connected chain)
        if !config.matrix_public_room_disabled {
            let req = SendRoomMessageRequest::with_message(&message, formatted_message);
            self.dispatch_message(&self.public_room_id, &req).await?;
        }

        Ok(())
    }

    pub async fn send_callout_message(
        &self,
        message: &str,
        formatted_message: Option<&str>,
    ) -> Result<(), MatrixError> {
        if self.disabled {
            return Ok(());
        }
        let config = CONFIG.clone();
        // Send message to callout public rooms
        if !config.matrix_public_room_disabled {
            for room_id in self.callout_public_room_ids.iter() {
                let req = SendRoomMessageRequest::with_message(&message, formatted_message);
                self.dispatch_message(&room_id, &req).await?;
            }
        }

        Ok(())
    }

    pub async fn send_private_file(
        &self,
        to_user_id: &str,
        filename: &str,
        url: &str,
        file_info: Option<FileInfo>,
    ) -> Result<(), MatrixError> {
        if self.disabled {
            return Ok(());
        }
        // Get or create user private room
        if let Some(private_room) = self.get_or_create_private_room(to_user_id).await? {
            // Send message to the private room (bot <=> user)
            let req = SendRoomMessageRequest::with_attachment(&filename, &url, file_info);
            self.dispatch_message(&private_room.room_id, &req).await?;
        }

        Ok(())
    }

    #[async_recursion]
    async fn dispatch_message(
        &self,
        room_id: &str,
        request: &SendRoomMessageRequest,
    ) -> Result<Option<EventID>, MatrixError> {
        if self.disabled {
            return Ok(None);
        }
        match &self.access_token {
            Some(access_token) => {
                let client = self.client.clone();
                let res = client
                    .post(format!(
                        "{}/rooms/{}/send/m.room.message?access_token={}",
                        MATRIX_URL, room_id, access_token
                    ))
                    .json(request)
                    .send()
                    .await?;

                debug!("response {:?}", res);
                match res.status() {
                    reqwest::StatusCode::OK => {
                        let response = res.json::<SendRoomMessageResponse>().await?;
                        info!(
                            "messsage dispatched to room_id: {} (event_id: {})",
                            response.event_id, room_id
                        );
                        Ok(Some(response.event_id))
                    }
                    reqwest::StatusCode::TOO_MANY_REQUESTS => {
                        let response = res.json::<ErrorResponse>().await?;
                        warn!("Matrix {} -> Wait 5 seconds and try again", response.error);
                        thread::sleep(time::Duration::from_secs(5));
                        return self.dispatch_message(room_id, request).await;
                    }
                    _ => {
                        let response = res.json::<ErrorResponse>().await?;
                        Err(MatrixError::Other(response.error))
                    }
                }
            }
            None => Err(MatrixError::Other("access_token not defined".to_string())),
        }
    }

    // #[async_recursion]
    // async fn dispatch_file_message(
    //     &self,
    //     room_id: &str,
    //     filename: &str,
    //     url: &str,
    //     file_info: Option<FileInfo>,
    // ) -> Result<Option<EventID>, MatrixError> {
    //     if self.disabled {
    //         return Ok(None);
    //     }
    //     match &self.access_token {
    //         Some(access_token) => {
    //             let client = self.client.clone();
    //             let req = if let Some(file_info) = file_info {
    //                 SendRoomMessageRequest {
    //                     msgtype: "m.file".to_string(),
    //                     body: filename.to_string(),
    //                     url: url.to_string(),
    //                     info: file_info
    //                 }
    //             } else {
    //                 SendRoomMessageRequest {
    //                     msgtype: "m.text".to_string(),
    //                     body: message.to_string(),
    //                     url: url.to_string(),
    //                     ..Default::default()
    //                 }
    //             };

    //             let res = client
    //                 .post(format!(
    //                     "{}/rooms/{}/send/m.room.message?access_token={}",
    //                     MATRIX_URL, room_id, access_token
    //                 ))
    //                 .json(&req)
    //                 .send()
    //                 .await?;

    //             debug!("response {:?}", res);
    //             match res.status() {
    //                 reqwest::StatusCode::OK => {
    //                     let response = res.json::<SendRoomMessageResponse>().await?;
    //                     info!(
    //                         "messsage dispatched to room_id: {} (event_id: {})",
    //                         response.event_id, room_id
    //                     );
    //                     Ok(Some(response.event_id))
    //                 }
    //                 reqwest::StatusCode::TOO_MANY_REQUESTS => {
    //                     let response = res.json::<ErrorResponse>().await?;
    //                     warn!("Matrix {} -> Wait 5 seconds and try again", response.error);
    //                     thread::sleep(time::Duration::from_secs(5));
    //                     return self
    //                         .dispatch_file_message(room_id, message, formatted_message)
    //                         .await;
    //                 }
    //                 _ => {
    //                     let response = res.json::<ErrorResponse>().await?;
    //                     Err(MatrixError::Other(response.error))
    //                 }
    //             }
    //         }
    //         None => Err(MatrixError::Other("access_token not defined".to_string())),
    //     }
    // }
}
