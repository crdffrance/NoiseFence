//! Invitation tokens are one-use credentials. Plaintext exists only in the create response.
use super::*;

pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/admin/invitations", get(list).post(create))
        .route("/admin/invitations/revoke", post(revoke))
        .route("/onboarding/check", post(check))
        .route("/onboarding/accept", post(accept))
        .route("/admin/filtering/preview", post(preview))
}
pub(super) fn grants(cfg: &Config, username: &str, addresses: &mut Vec<String>) -> Result<()> {
    ensure!(
        !username.is_empty()
            && username.len() <= 100
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b)),
        "Identifiant invalide."
    );
    ensure!(addresses.len() <= 1000, "Trop d’accès.");
    for address in addresses.iter_mut() {
        let (local, domain) = address
            .rsplit_once('@')
            .ok_or_else(|| anyhow::anyhow!("Adresse invalide."))?;
        ensure!(
            cfg.domains
                .iter()
                .any(|d| d.name.eq_ignore_ascii_case(domain)),
            "Domaine non configuré."
        );
        *address = if local == "*" {
            format!("*@{}", domain.to_ascii_lowercase())
        } else {
            cfg.recipient(address)
                .ok_or_else(|| anyhow::anyhow!("Destinataire non configuré."))?
                .destination
        };
    }
    addresses.sort();
    addresses.dedup();
    Ok(())
}
fn invalid() -> Error {
    Error(StatusCode::BAD_REQUEST,"Invitation invalide, expirée ou déjà utilisée. Demandez un nouveau lien à votre administrateur.".into())
}
fn rate(app: &App, h: &HeaderMap, token: &str) -> ApiResult<String> {
    origin(app, h)?;
    let mut limiter = app.limiter.lock().unwrap();
    limiter.retain(|_, (expiry, _)| *expiry > now());
    let attempts = limiter
        .entry("invitation-global".into())
        .or_insert((now() + 60, 0));
    attempts.1 += 1;
    if attempts.1 > 60 {
        return Err(Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Réessayez dans une minute.".into(),
        ));
    }
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    Ok(message::digest(token.as_bytes()))
}
fn authorized(db: &rusqlite::Connection, username: &str) -> Result<i64> {
    Ok(db.query_row("SELECT COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0",[username],|r|r.get(0))?)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invite {
    username: String,
    admin: bool,
    addresses: Vec<String>,
    days: u16,
}
async fn create(
    State(app): State<App>,
    h: HeaderMap,
    Json(mut body): Json<Invite>,
) -> ApiResult<Json<Value>> {
    let actor = admin::administrator(&app, &h, true).await?;
    if !(1..=7).contains(&body.days) || (!body.admin && body.addresses.is_empty()) {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Choisissez des accès et une durée de 1 à 7 jours.".into(),
        ));
    }
    grants(&app.effective(), &body.username, &mut body.addresses)
        .map_err(|e| Error(StatusCode::BAD_REQUEST, e.to_string()))?;
    let token = random_token();
    let digest = message::digest(token.as_bytes());
    let id = uuid::Uuid::new_v4().to_string();
    let saved = id.clone();
    let expires = now() + i64::from(body.days) * 86400;
    app.store.run(move|db| {
        let tx=db.transaction()?;let version=authorized(&tx,&actor.username)?;
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1)",[&body.username],|r|r.get(0))?;
        ensure!(!exists,"Ce compte existe déjà. Utilisez la gestion des comptes.");
        let count:i64=tx.query_row("SELECT COUNT(*) FROM console_invitations WHERE accepted IS NULL AND revoked IS NULL AND expires>?1",[now()],|r|r.get(0))?;
        ensure!(count<1000,"Maximum de 1 000 invitations actives atteint.");
        // Reissuing for the same username invalidates every previous pending link.
        tx.execute("UPDATE console_invitations SET revoked=?2,version=version+1 WHERE username=?1 AND accepted IS NULL AND revoked IS NULL",params![body.username,now()])?;
        tx.execute("INSERT INTO console_invitations(id,token_hash,username,admin,addresses,creator,creator_version,created,expires) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![saved,digest,body.username,body.admin,serde_json::to_string(&body.addresses)?,actor.username,version,now(),expires])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'invitation_create',?3)",params![now(),actor.username,saved])?;
        tx.commit()?;Ok(())
    }).await.map_err(|e|Error(StatusCode::CONFLICT,e.to_string()))?;
    Ok(Json(
        json!({"id":id,"expires":expires,"url":format!("{}/#invite={token}",app.config.web.public_origin.trim_end_matches('/'))}),
    ))
}
async fn list(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    admin::administrator(&app, &h, false).await?;
    Ok(Json(json!(app.store.read(|db| {
        let mut q=db.prepare("SELECT i.id,i.username,i.admin,i.addresses,i.created,i.expires,i.version,CASE WHEN i.accepted IS NOT NULL THEN 'accepted' WHEN i.revoked IS NOT NULL OR NOT EXISTS(SELECT 1 FROM users u LEFT JOIN console_user_versions v ON u.username=v.username WHERE u.username=i.creator AND u.admin=1 AND u.disabled=0 AND COALESCE(v.version,0)=i.creator_version) THEN 'revoked' WHEN i.expires<=?1 THEN 'expired' ELSE 'pending' END FROM console_invitations i ORDER BY i.created DESC,i.id LIMIT 1000")?;
        Ok(q.query_map([now()],|r|Ok(json!({"id":r.get::<_,String>(0)?,"username":r.get::<_,String>(1)?,"admin":r.get::<_,bool>(2)?,"addresses":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or_default(),"created":r.get::<_,i64>(4)?,"expires":r.get::<_,i64>(5)?,"version":r.get::<_,i64>(6)?,"status":r.get::<_,String>(7)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await?)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Revoke {
    id: String,
    version: i64,
}
async fn revoke(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Revoke>,
) -> ApiResult<Json<Value>> {
    let actor = admin::administrator(&app, &h, true).await?;
    app.store.run(move|db| {let tx=db.transaction()?;authorized(&tx,&actor.username)?;
        let changed=tx.execute("UPDATE console_invitations SET revoked=?3,version=version+1 WHERE id=?1 AND version=?2 AND accepted IS NULL AND revoked IS NULL",params![body.id,body.version,now()])?;
        ensure!(changed==1,"Invitation modifiée ou déjà utilisée.");
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'invitation_revoke',?3)",params![now(),actor.username,body.id])?;tx.commit()?;Ok(())
    }).await.map_err(|_|Error(StatusCode::CONFLICT,"Invitation modifiée ou déjà utilisée. Rechargez la liste.".into()))?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    token: String,
}
struct Claim {
    id: String,
    username: String,
    admin: bool,
    addresses: Vec<String>,
}
fn claim(db: &rusqlite::Connection, hash: &str) -> Result<Claim> {
    let (id,username,admin,addresses):(String,String,bool,String)=db.query_row("SELECT i.id,i.username,i.admin,i.addresses FROM console_invitations i JOIN users u ON u.username=i.creator LEFT JOIN console_user_versions v ON v.username=u.username WHERE i.token_hash=?1 AND i.revoked IS NULL AND i.accepted IS NULL AND i.expires>?2 AND u.admin=1 AND u.disabled=0 AND COALESCE(v.version,0)=i.creator_version AND NOT EXISTS(SELECT 1 FROM users target WHERE target.username=i.username)",params![hash,now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    Ok(Claim {
        id,
        username,
        admin,
        addresses: serde_json::from_str(&addresses)?,
    })
}
async fn check(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Token>,
) -> ApiResult<Json<Value>> {
    let hash = rate(&app, &h, &body.token)?;
    let c = app
        .store
        .read(move |db| claim(db, &hash))
        .await
        .map_err(|_| invalid())?;
    Ok(Json(
        json!({"username":c.username,"admin":c.admin,"addresses":c.addresses}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Accept {
    token: String,
    password: String,
    confirmation: String,
}
async fn accept(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Accept>,
) -> ApiResult<Json<Value>> {
    let hash = rate(&app, &h, &body.token)?;
    if body.password != body.confirmation || !(12..=128).contains(&body.password.len()) {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Les mots de passe doivent être identiques et contenir 12 à 128 octets.".into(),
        ));
    }
    let verify_hash = hash.clone();
    app.store
        .read(move |db| claim(db, &verify_hash))
        .await
        .map_err(|_| invalid())?;
    let permit = app.hashing.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Réessayez dans quelques instants.".into(),
        )
    })?;
    let password = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&body.password)
    })
    .await
    .map_err(anyhow::Error::from)??;
    let (cfg, revision) = if let Some(control) = &app.control {
        let snapshot = control.snapshot();
        (snapshot.config.clone(), Some(snapshot.revision))
    } else {
        (app.config.clone(), None)
    };
    let username=app.store.run(move|db| {
        let tx=db.transaction()?;let mut c=claim(&tx,&hash)?;
        if let Some(expected)=revision {let current:i64=tx.query_row("SELECT COALESCE(MAX(id),0) FROM console_revisions",[],|r|r.get(0))?;ensure!(current==expected,"Configuration modifiée, réessayez.");}
        let intended=c.addresses.clone();grants(&cfg,&c.username,&mut c.addresses)?;
        ensure!(intended==c.addresses,"Les accès ont changé. Demandez un nouveau lien.");
        let count:i64=tx.query_row("SELECT COUNT(*) FROM users",[],|r|r.get(0))?;ensure!(count<1000,"Limite de comptes atteinte.");
        tx.execute("INSERT INTO users(username,password,admin) VALUES(?1,?2,?3)",params![c.username,password,c.admin])?;
        for address in c.addresses {tx.execute("INSERT INTO grants(username,address) VALUES(?1,?2)",params![c.username,address])?;}
        tx.execute("INSERT INTO console_user_versions(username,version) VALUES(?1,1)",[&c.username])?;
        tx.execute("UPDATE console_invitations SET accepted=?2,version=version+1 WHERE id=?1",params![c.id,now()])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'invitation_accept',?3)",params![now(),c.username,c.id])?;
        tx.commit()?;Ok(c.username)
    }).await.map_err(|_|invalid())?;
    Ok(Json(json!({"ok":true,"username":username})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    policy: crate::custom_filtering::Policy,
    recipient: String,
    subject: String,
    sender: String,
    body: String,
    score: f64,
}
async fn preview(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Preview>,
) -> ApiResult<Json<Value>> {
    admin::administrator(&app, &h, true).await?;
    let cfg = app.effective();
    body.policy
        .validate(&cfg)
        .map_err(|e| Error(StatusCode::BAD_REQUEST, e.to_string()))?;
    if !body.score.is_finite()
        || !(0.0..=100.0).contains(&body.score)
        || body.body.len() > 100_000
        || body.subject.len() > 2000
        || body.sender.len() > 320
    {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Faits de simulation invalides.".into(),
        ));
    }
    let recipient = cfg.recipient(&body.recipient).ok_or_else(|| {
        Error(
            StatusCode::BAD_REQUEST,
            "Destinataire non configuré.".into(),
        )
    })?;
    let mut scan = crate::engine::Scan {
        complete: true,
        score: body.score,
        ..Default::default()
    };
    scan.decision = Some(crate::fusion::runtime::Decision::legacy(
        &scan,
        cfg.filter.threshold,
    ));
    let mut facts = crate::custom_filtering::Facts::default();
    use crate::custom_filtering::Field;
    facts.put(Field::EnvelopeFrom, &body.sender);
    facts.put(
        Field::FromDomain,
        body.sender.rsplit_once('@').map(|(_, d)| d).unwrap_or(""),
    );
    facts.put(Field::Subject, &body.subject);
    facts.put(Field::Body, &body.body);
    facts.put(Field::Score, &body.score.to_string());
    let assessment =
        crate::custom_filtering::assess(&body.policy, &cfg, &scan, &facts, &recipient, now());
    Ok(Json(
        json!({"simulation":true,"assessment":assessment,"note":"Simulation des règles avec les faits saisis. Les contrôles DMARC, antivirus et réputation ne sont pas exécutés."}),
    ))
}
