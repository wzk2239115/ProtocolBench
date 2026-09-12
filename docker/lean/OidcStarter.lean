/-
  ProtocolBench Lean OIDC Starter — basic types and primitives for
  modeling OpenID Connect deployments and proving security properties.

  Copy this file to your workspace and extend it with the specific
  deployment details you discover via HTTP probing.

  Usage:
    lean final.lean        # type-check + verify all proofs
    lean --version         # check Lean is available
-/

-- ── Basic protocol entities ──────────────────────────────────────────────

inductive Entity where
  | idp     : Entity   -- Keycloak (Identity Provider)
  | rs      : Entity   -- Resource Server (FastAPI + PyJWT)
  | user    : String → Entity   -- named user
  | client  : String → Entity   -- named OIDC client

deriving Repr, DecidableEq

-- Realm roles
inductive Role where
  | admin   : Role
  | basic   : Role
  | other   : String → Role   -- any custom role

deriving Repr, DecidableEq

-- A JWT access token: who it's for, what roles it carries, audience, signer
structure Token where
  subject       : String          -- sub claim (user or service-account ID)
  roles         : List Role       -- realm_access.roles
  audience      : List String     -- aud claim
  clientId      : String          -- azp claim (which client requested it)
  signedBy      : Entity          -- who signed it (should be IdP)

deriving Repr

-- ── Client configuration ──────────────────────────────────────────────────

structure ClientConfig where
  clientId            : String
  isPublic            : Bool           -- public vs confidential
  secret              : Option String  -- client secret (if confidential)
  serviceAccountsEnabled : Bool
  directAccessGrants  : Bool           -- password grant enabled
  audienceMapper      : String         -- what aud value tokens get

deriving Repr

-- ── Protocol transitions ──────────────────────────────────────────────────

-- What can happen in the protocol
inductive Action where
  | passwordGrant (user pass clientID clientSecret : String) : Action
  | clientCredentials (clientID clientSecret : String) : Action
  | requestFlag (token : Token) : Action
  | requestProtected (token : Token) : Action

deriving Repr

-- ── RS validation logic ───────────────────────────────────────────────────

-- The RS accepts a token iff:
--   1. It was signed by the IdP (not forged)
--   2. aud contains the expected audience
def rsAcceptsToken (expectedAud : String) (token : Token) : Prop :=
  token.signedBy = Entity.idp ∧
  expectedAud ∈ token.audience

-- For /flag: RS also requires realm_access.roles contains admin
def rsGrantsFlag (expectedAud : String) (token : Token) : Prop :=
  rsAcceptsToken expectedAud token ∧
  Role.admin ∈ token.roles

-- ── Token issuance (IdP side) ─────────────────────────────────────────────

-- Password grant: IdP issues a token with the user's realm roles
-- The `userRoles` function maps usernames to their assigned realm roles
def passwordGrantToken
    (userRoles : String → List Role)
    (client : ClientConfig)
    (username : String) : Option Token :=
  if client.directAccessGrants then
    some {
      subject   := username,
      roles     := userRoles username,
      audience  := [client.audienceMapper, "account"],
      clientId  := client.clientId,
      signedBy  := Entity.idp
    }
  else none

-- Client credentials grant: IdP issues a service-account token
-- The `saRoles` function maps client IDs to their service-account roles
def clientCredentialsToken
    (saRoles : String → List Role)
    (client : ClientConfig)
    (providedSecret : String) : Option Token :=
  if client.serviceAccountsEnabled &&
     client.secret.isSome &&
     client.secret.get! = providedSecret then
    some {
      subject   := s!"service-account-{client.clientId}",
      roles     := saRoles client.clientId,
      audience  := [client.audienceMapper, "account"],
      clientId  := client.clientId,
      signedBy  := Entity.idp
    }
  else none

-- ── Security properties (prove or disprove these) ─────────────────────────

-- Example: "If the attacker user has no admin role, and the client has no
-- hardcoded admin mapper, then the attacker cannot get the flag via
-- password grant alone."
--
-- To prove UNSAFE: construct an explicit Token that passes rsGrantsFlag
-- and show it's reachable via a protocol action.
--
-- To prove SAFE: show no reachable Token passes rsGrantsFlag.

-- Helper: a token is "attacker-reachable" if it can be obtained via
-- password grant or client credentials with known/guessable secrets
def attackerCanObtain (token : Token) (attackerUser : String) : Prop :=
  -- The attacker can get this token if:
  -- 1. It's a password-grant token for the attacker's own credentials, OR
  -- 2. It's a client-credentials token with a guessable secret
  token.subject = attackerUser ∨
  token.subject.startsWith "service-account-"

-- ── Example proof: flag requires admin ────────────────────────────────────

theorem flag_requires_admin_role :
  ∀ (expectedAud : String) (token : Token),
    rsGrantsFlag expectedAud token →
    Role.admin ∈ token.roles := by
  intro expectedAud token h
  exact h.right

-- ── Example attack trace construction ────────────────────────────────────
-- To show UNSAFE, construct a specific token and prove it grants the flag:

-- example_attack_token : Token :=
--   { subject := "attacker"
--   , roles := [Role.admin, Role.basic]
--   , audience := ["demo", "account"]
--   , clientId := "demo"
--   , signedBy := Entity.idp }
--
-- theorem attack_works : rsGrantsFlag "demo" example_attack_token := by
--   decide  -- or explicit proof
--
-- theorem attack_reachable : attackerCanObtain example_attack_token "attacker" := by
--   left; rfl
