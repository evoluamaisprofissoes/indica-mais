const SESSION_DAYS = 7;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8"
};


/*
==================================================
RESPOSTAS
==================================================
*/

function json(data, status = 200) {

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: CORS
    }
  );
}


function error(
  message,
  status = 400
) {

  return json(
    {
      success: false,
      error: message
    },
    status
  );
}

function csvEscape(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function csvResponse(rows, columns) {
  const lines = [
    columns.map(c => csvEscape(c.label)).join(";")
  ];
  for (const row of rows) {
    lines.push(columns.map(c => csvEscape(row[c.key])).join(";"));
  }
  return new Response("\uFEFF" + lines.join("\n"), {
    status: 200,
    headers: {
      ...CORS,
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="indica-mais-${Date.now()}.csv"`
    }
  });
}


/*
==================================================
UTILITÁRIOS
==================================================
*/

function token() {

  const bytes =
    new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return Array
    .from(bytes)
    .map(
      b =>
        b.toString(16)
         .padStart(2, "0")
    )
    .join("");
}


function ticketCode() {

  const bytes =
    new Uint8Array(8);

  crypto.getRandomValues(bytes);

  return (
    "IND-" +
    Array
      .from(bytes)
      .map(
        b =>
          b.toString(16)
           .padStart(2, "0")
      )
      .join("")
      .toUpperCase()
  );
}


function authToken(request) {

  const header =
    request.headers.get(
      "Authorization"
    ) || "";

  if (
    !header.startsWith(
      "Bearer "
    )
  ) {

    return null;
  }

  return header
    .substring(7)
    .trim();
}


function normalizePhone(value) {

  return String(
    value || ""
  ).replace(
    /\D/g,
    ""
  );
}


/*
==================================================
ADMIN - AUTENTICAÇÃO
==================================================
*/

async function getAdmin(
  request,
  env
) {

  const sessionToken =
    authToken(request);

  if (!sessionToken) {
    return null;
  }

  return await env.DB
    .prepare(`
      SELECT
        a.id,
        a.name,
        a.email,
        a.role
      FROM sessions s
      JOIN admins a
        ON a.id = s.admin_id
      WHERE s.token = ?
        AND s.expires_at > datetime('now')
        AND a.active = 1
      LIMIT 1
    `)
    .bind(sessionToken)
    .first();
}


/*
==================================================
ALUNO - AUTENTICAÇÃO
==================================================
*/

async function getStudent(
  request,
  env
) {

  const sessionToken =
    authToken(request);

  if (!sessionToken) {
    return null;
  }

  return await env.DB
    .prepare(`
      SELECT
        s.id,
        s.name,
        s.whatsapp,
        s.phone,
        s.email,
        s.active
      FROM student_sessions ss
      JOIN students s
        ON s.id = ss.student_id
      WHERE ss.token = ?
        AND ss.expires_at > datetime('now')
        AND s.active = 1
      LIMIT 1
    `)
    .bind(sessionToken)
    .first();
}


/*
==================================================
SENHAS
==================================================
*/

async function passwordHash(
  password
) {

  const salt =
    crypto.getRandomValues(
      new Uint8Array(16)
    );

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        password
      ),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256"
      },
      key,
      256
    );

  const saltHex =
    Array
      .from(salt)
      .map(
        b =>
          b.toString(16)
           .padStart(2, "0")
      )
      .join("");

  const hashHex =
    Array
      .from(
        new Uint8Array(bits)
      )
      .map(
        b =>
          b.toString(16)
           .padStart(2, "0")
      )
      .join("");

  return (
    `${saltHex}$100000$${hashHex}`
  );
}


async function verifyPassword(
  password,
  stored
) {

  if (!stored) {
    return false;
  }

  const parts =
    stored.split("$");

  if (
    parts.length !== 3
  ) {

    return false;
  }

  const saltHex =
    parts[0];

  const iterations =
    Number(parts[1]);

  const expected =
    parts[2];

  const salt =
    new Uint8Array(
      saltHex
        .match(/.{1,2}/g)
        .map(
          x =>
            parseInt(
              x,
              16
            )
        )
    );

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(
        password
      ),
      {
        name: "PBKDF2"
      },
      false,
      ["deriveBits"]
    );

  const bits =
    await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );

  const actual =
    Array
      .from(
        new Uint8Array(bits)
      )
      .map(
        b =>
          b.toString(16)
           .padStart(2, "0")
      )
      .join("");

  return (
    actual === expected
  );
}


/*
==================================================
AUDITORIA
==================================================
*/

async function audit(
  env,
  admin,
  action,
  entityType,
  entityId,
  details = {}
) {

  await env.DB
    .prepare(`
      INSERT INTO audit_logs (
        id,
        admin_id,
        action,
        entity_type,
        entity_id,
        details_json,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `)
    .bind(
      crypto.randomUUID(),
      admin
        ? admin.id
        : null,
      action,
      entityType,
      entityId || null,
      JSON.stringify(details),
      new Date().toISOString()
    )
    .run();
}


/*
==================================================
TICKET ÚNICO
==================================================
*/

async function uniqueTicket(
  env
) {

  for (
    let i = 0;
    i < 10;
    i++
  ) {

    const code =
      ticketCode();

    const exists =
      await env.DB
        .prepare(`
          SELECT id
          FROM tickets
          WHERE code = ?
          LIMIT 1
        `)
        .bind(code)
        .first();

    if (!exists) {

      return code;
    }
  }

  throw new Error(
    "Não foi possível gerar um ticket único."
  );
}


/*
==================================================
WORKER
==================================================
*/

export default {

  async fetch(
    request,
    env
  ) {

    if (
      request.method ===
      "OPTIONS"
    ) {

      return new Response(
        null,
        {
          status: 204,
          headers: CORS
        }
      );
    }


    const url =
      new URL(request.url);


    try {


      /*
      ==========================================
      HEALTH
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/health"
      ) {

        const result =
          await env.DB
            .prepare(
              "SELECT 1 AS ok"
            )
            .first();

        return json({

          success: true,

          api:
            "online",

          database:
            result?.ok === 1
              ? "online"
              : "offline",

          timestamp:
            new Date().toISOString()

        });
      }


      /*
      ==========================================
      CAMPANHA PÚBLICA
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/campaign"
      ) {

        const campaign =
          await env.DB
            .prepare(`
              SELECT *
              FROM campaigns
              WHERE status = 'active'
              ORDER BY created_at DESC
              LIMIT 1
            `)
            .first();

        if (!campaign) {

          return error(
            "Nenhuma campanha ativa.",
            404
          );
        }

        return json({

          success: true,

          campaign

        });
      }


      /*
      ==========================================
      STATS PÚBLICOS
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/stats"
      ) {

        const campaign =
          await env.DB
            .prepare(`
              SELECT id
              FROM campaigns
              WHERE status = 'active'
              ORDER BY created_at DESC
              LIMIT 1
            `)
            .first();

        if (!campaign) {

          return error(
            "Nenhuma campanha ativa.",
            404
          );
        }


        const results =
          await env.DB.batch([

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM referrals
              WHERE campaign_id = ?
            `)
            .bind(
              campaign.id
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM students
            `),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM enrollments
              WHERE campaign_id = ?
            `)
            .bind(
              campaign.id
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM tickets
              WHERE campaign_id = ?
                AND status = 'available'
            `)
            .bind(
              campaign.id
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM prizes
              WHERE campaign_id = ?
                AND active = 1
            `)
            .bind(
              campaign.id
            )

          ]);


        return json({

          success: true,

          stats: {

            referrals:
              Number(
                results[0]
                  .results[0]
                  .total
              ),

            students:
              Number(
                results[1]
                  .results[0]
                  .total
              ),

            enrollments:
              Number(
                results[2]
                  .results[0]
                  .total
              ),

            tickets:
              Number(
                results[3]
                  .results[0]
                  .total
              ),

            prizes:
              Number(
                results[4]
                  .results[0]
                  .total
              )
          }
        });
      }


      /*
      ==========================================
      ALUNO - LOGIN
      ==========================================
      */

      if (
        request.method === "POST" &&
        url.pathname ===
          "/api/student/login"
      ) {

        const body =
          await request.json();

        const name =
          String(
            body.name || ""
          ).trim();

        const whatsapp =
          normalizePhone(
            body.whatsapp
          );


        if (!whatsapp) {

          return error(
            "Informe seu WhatsApp.",
            422
          );
        }


        if (
          whatsapp.length < 10
        ) {

          return error(
            "WhatsApp inválido.",
            422
          );
        }


        let student =
          await env.DB
            .prepare(`
              SELECT *
              FROM students
              WHERE whatsapp = ?
              LIMIT 1
            `)
            .bind(whatsapp)
            .first();


        /*
        ----------------------------------------
        CRIA ALUNO
        ----------------------------------------
        */

        if (!student) {

          if (!name) {

            return error(
              "Informe seu nome.",
              422
            );
          }


          const studentId =
            crypto.randomUUID();

          const now =
            new Date().toISOString();


          await env.DB
            .prepare(`
              INSERT INTO students (
                id,
                name,
                whatsapp,
                phone,
                email,
                active,
                created_at,
                updated_at
              )
              VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            `)
            .bind(
              studentId,
              name,
              whatsapp,
              whatsapp,
              "",
              now,
              now
            )
            .run();


          student =
            await env.DB
              .prepare(`
                SELECT *
                FROM students
                WHERE id = ?
                LIMIT 1
              `)
              .bind(studentId)
              .first();

        } else {


          if (!student.active) {

            return error(
              "Aluno inativo.",
              403
            );
          }


          if (
            name &&
            name !== student.name
          ) {

            await env.DB
              .prepare(`
                UPDATE students
                SET
                  name = ?,
                  updated_at = ?
                WHERE id = ?
              `)
              .bind(
                name,
                new Date().toISOString(),
                student.id
              )
              .run();

            student.name =
              name;
          }
        }


        /*
        ----------------------------------------
        SESSÃO
        ----------------------------------------
        */

        const sessionToken =
          token();

        const expires =
          new Date(
            Date.now() +
            SESSION_DAYS *
            24 *
            60 *
            60 *
            1000
          ).toISOString();


        await env.DB
          .prepare(`
            INSERT INTO student_sessions (
              id,
              token,
              student_id,
              expires_at,
              created_at
            )
            VALUES (?, ?, ?, ?, ?)
          `)
          .bind(
            crypto.randomUUID(),
            sessionToken,
            student.id,
            expires,
            new Date().toISOString()
          )
          .run();


        return json({

          success: true,

          token:
            sessionToken,

          expires_at:
            expires,

          student: {

            id:
              student.id,

            name:
              student.name,

            whatsapp:
              student.whatsapp,

            email:
              student.email || ""

          }

        });
      }


      /*
      ==========================================
      ALUNO - ME
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/student/me"
      ) {

        const student =
          await getStudent(
            request,
            env
          );


        if (!student) {

          return error(
            "Sessão do aluno inválida ou expirada.",
            401
          );
        }


        return json({

          success: true,

          student

        });
      }


      /*
      ==========================================
      ALUNO - LOGOUT
      ==========================================
      */

      if (
        request.method === "POST" &&
        url.pathname ===
          "/api/student/logout"
      ) {

        const sessionToken =
          authToken(request);


        if (sessionToken) {

          await env.DB
            .prepare(`
              DELETE FROM student_sessions
              WHERE token = ?
            `)
            .bind(
              sessionToken
            )
            .run();
        }


        return json({
          success: true
        });
      }


      /*
      ==========================================
      ALUNO - DASHBOARD
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/student/dashboard"
      ) {

        const student =
          await getStudent(
            request,
            env
          );


        if (!student) {

          return error(
            "Não autenticado.",
            401
          );
        }


        const campaign =
          await env.DB
            .prepare(`
              SELECT *
              FROM campaigns
              WHERE status = 'active'
              ORDER BY created_at DESC
              LIMIT 1
            `)
            .first();


        if (!campaign) {

          return error(
            "Nenhuma campanha ativa.",
            404
          );
        }


        const results =
          await env.DB.batch([

            env.DB.prepare(`
              SELECT
                id,
                campaign_id,
                student_id,
                lead_name,
                lead_whatsapp,
                lead_email,
                status,
                created_at,
                eligible_at,
                confirmed_at
              FROM referrals
              WHERE student_id = ?
                AND campaign_id = ?
              ORDER BY created_at DESC
            `)
            .bind(
              student.id,
              campaign.id
            ),

            env.DB.prepare(`
              SELECT
                id,
                campaign_id,
                student_id,
                referral_id,
                code,
                status,
                created_at,
                used_at,
                revoked_at,
                revoked_reason
              FROM tickets
              WHERE student_id = ?
                AND campaign_id = ?
              ORDER BY created_at DESC
            `)
            .bind(
              student.id,
              campaign.id
            ),

            env.DB.prepare(`
              SELECT
                d.id,
                d.ticket_id,
                d.prize_id,
                d.drawn_at,
                p.name AS prize_name,
                p.description AS prize_description,
                p.icon AS prize_icon,
                p.image_url AS prize_image
              FROM draws d
              JOIN prizes p
                ON p.id = d.prize_id
              WHERE d.student_id = ?
                AND d.campaign_id = ?
              ORDER BY d.drawn_at DESC
            `)
            .bind(
              student.id,
              campaign.id
            )

          ]);


        return json({

          success: true,

          student,

          campaign,

          referrals:
            results[0].results || [],

          tickets:
            results[1].results || [],

          wins:
            results[2].results || []

        });
      }


      /*
      ==========================================
      ALUNO - NOVA INDICAÇÃO
      ==========================================
      */

      if (
        request.method === "POST" &&
        url.pathname ===
          "/api/student/referrals"
      ) {

        const student =
          await getStudent(
            request,
            env
          );


        if (!student) {

          return error(
            "Não autenticado.",
            401
          );
        }


        const body =
          await request.json();


        const leadName =
          String(
            body.name || ""
          ).trim();


        const leadWhatsapp =
          normalizePhone(
            body.whatsapp
          );


        const leadEmail =
          String(
            body.email || ""
          ).trim();


        if (!leadName) {

          return error(
            "Informe o nome do indicado.",
            422
          );
        }


        if (
          !leadWhatsapp ||
          leadWhatsapp.length < 10
        ) {

          return error(
            "Informe um WhatsApp válido.",
            422
          );
        }


        const campaign =
          await env.DB
            .prepare(`
              SELECT *
              FROM campaigns
              WHERE status = 'active'
              ORDER BY created_at DESC
              LIMIT 1
            `)
            .first();


        if (!campaign) {

          return error(
            "Nenhuma campanha ativa.",
            404
          );
        }


        /*
        ----------------------------------------
        EVITA DUPLICIDADE
        ----------------------------------------
        */

        const existing =
          await env.DB
            .prepare(`
              SELECT
                id,
                student_id
              FROM referrals
              WHERE campaign_id = ?
                AND lead_whatsapp = ?
                AND status != 'cancelled'
              LIMIT 1
            `)
            .bind(
              campaign.id,
              leadWhatsapp
            )
            .first();


        if (existing) {

          if (
            existing.student_id ===
            student.id
          ) {

            return error(
              "Você já indicou este WhatsApp nesta campanha.",
              409
            );
          }


          return error(
            "Este WhatsApp já foi indicado nesta campanha.",
            409
          );
        }


        const now =
          new Date();


        const eligibleAt =
          new Date(
            now.getTime() +
            7 *
            24 *
            60 *
            60 *
            1000
          );


        const referralId =
          crypto.randomUUID();


        await env.DB
          .prepare(`
            INSERT INTO referrals (
              id,
              campaign_id,
              student_id,
              lead_name,
              lead_whatsapp,
              lead_phone,
              lead_email,
              status,
              created_at,
              eligible_at
            )
            VALUES (
              ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?
            )
          `)
          .bind(
            referralId,
            campaign.id,
            student.id,
            leadName,
            leadWhatsapp,
            leadWhatsapp,
            leadEmail,
            now.toISOString(),
            eligibleAt.toISOString()
          )
          .run();


        return json({

          success: true,

          message:
            "Indicação registrada com sucesso.",

          referral: {

            id:
              referralId,

            campaign_id:
              campaign.id,

            student_id:
              student.id,

            lead_name:
              leadName,

            lead_whatsapp:
              leadWhatsapp,

            status:
              "pending",

            created_at:
              now.toISOString(),

            eligible_at:
              eligibleAt.toISOString()

          }

        }, 201);
      }


      /*
      ==========================================
      ADMIN - LOGIN
      ==========================================
      */

      if (
        request.method === "POST" &&
        url.pathname ===
          "/api/admin/login"
      ) {

        const body =
          await request.json();


        const email =
          String(
            body.email || ""
          )
          .trim()
          .toLowerCase();


        const password =
          String(
            body.password || ""
          );


        if (
          !email ||
          !password
        ) {

          return error(
            "Informe e-mail e senha.",
            422
          );
        }


        const admin =
          await env.DB
            .prepare(`
              SELECT *
              FROM admins
              WHERE lower(email) = ?
                AND active = 1
              LIMIT 1
            `)
            .bind(email)
            .first();


        if (!admin) {

          return error(
            "Administrador não encontrado.",
            401
          );
        }


        /*
        ----------------------------------------
        PRIMEIRO ACESSO
        ----------------------------------------
        */

        if (!admin.password_hash) {

          const hash =
            await passwordHash(
              password
            );


          await env.DB
            .prepare(`
              UPDATE admins
              SET
                password_hash = ?,
                updated_at = datetime('now')
              WHERE id = ?
            `)
            .bind(
              hash,
              admin.id
            )
            .run();

        } else {

          const valid =
            await verifyPassword(
              password,
              admin.password_hash
            );


          if (!valid) {

            return error(
              "E-mail ou senha inválidos.",
              401
            );
          }
        }


        const sessionToken =
          token();


        const expires =
          new Date(
            Date.now() +
            SESSION_DAYS *
            24 *
            60 *
            60 *
            1000
          ).toISOString();


        await env.DB
          .prepare(`
            INSERT INTO sessions (
              id,
              token,
              admin_id,
              expires_at,
              created_at
            )
            VALUES (?, ?, ?, ?, ?)
          `)
          .bind(
            crypto.randomUUID(),
            sessionToken,
            admin.id,
            expires,
            new Date().toISOString()
          )
          .run();


        await audit(
          env,
          admin,
          "login",
          "admin",
          admin.id
        );


        return json({

          success: true,

          token:
            sessionToken,

          expires_at:
            expires,

          admin: {

            id:
              admin.id,

            name:
              admin.name,

            email:
              admin.email,

            role:
              admin.role

          }

        });
      }


      /*
      ==========================================
      ADMIN - LOGOUT
      ==========================================
      */

      if (
        request.method === "POST" &&
        url.pathname ===
          "/api/admin/logout"
      ) {

        const sessionToken =
          authToken(request);


        if (sessionToken) {

          await env.DB
            .prepare(`
              DELETE FROM sessions
              WHERE token = ?
            `)
            .bind(
              sessionToken
            )
            .run();
        }


        return json({
          success: true
        });
      }


      /*
      ==========================================
      ADMIN - ME
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/admin/me"
      ) {

        const admin =
          await getAdmin(
            request,
            env
          );


        if (!admin) {

          return error(
            "Não autenticado.",
            401
          );
        }


        return json({

          success: true,

          admin

        });
      }


      /*
      ==========================================
      PROTEÇÃO DAS ROTAS ADMIN
      ==========================================
      */

      let admin = null;


      if (
        url.pathname.startsWith(
          "/api/admin/"
        )
      ) {

        admin =
          await getAdmin(
            request,
            env
          );


        if (!admin) {

          return error(
            "Não autenticado.",
            401
          );
        }
      }


      /*
      ==========================================
      ADMIN - CAMPANHAS / CONFIGURAÇÃO
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname === "/api/admin/campaigns"
      ) {
        const result = await env.DB.prepare(`
          SELECT * FROM campaigns
          ORDER BY CASE status
            WHEN 'active' THEN 0
            WHEN 'draft' THEN 1
            WHEN 'paused' THEN 2
            WHEN 'finished' THEN 3
            WHEN 'archived' THEN 4
            ELSE 5 END,
            created_at DESC
        `).all();
        return json({ success:true, campaigns: result.results || [] });
      }

      if (
        request.method === "POST" &&
        url.pathname === "/api/admin/campaigns"
      ) {
        const body = await request.json();
        const name = String(body.name || "").trim();
        const title = String(body.title || "").trim();
        if (!name || !title) return error("Nome e título da campanha são obrigatórios.", 422);
        const status = ["draft","active","paused","finished","archived"].includes(body.status) ? body.status : "draft";
        const id = crypto.randomUUID();
        const now = new Date().toISOString();
        if (status === "active") {
          await env.DB.prepare(`UPDATE campaigns SET status='archived', updated_at=? WHERE status='active'`).bind(now).run();
        }
        await env.DB.prepare(`
          INSERT INTO campaigns (
            id,name,badge,title,subtitle,logo_text,primary_color,secondary_color,
            banner_url,logo_url,background_url,starts_at,ends_at,status,created_at,updated_at
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        `).bind(
          id,name,String(body.badge||"CAMPANHA ATIVA"),title,String(body.subtitle||""),String(body.logo_text||"Indica+"),
          String(body.primary_color||"#6d28d9"),String(body.secondary_color||"#8b5cf6"),String(body.banner_url||""),
          String(body.logo_url||""),String(body.background_url||""),body.starts_at||null,body.ends_at||null,status,now,now
        ).run();
        await audit(env,admin,"campaign_created","campaign",id,{name,status});
        return json({success:true,campaign:await env.DB.prepare(`SELECT * FROM campaigns WHERE id=?`).bind(id).first()},201);
      }

      const campaignMatch = url.pathname.match(/^\/api\/admin\/campaigns\/([^/]+)$/);
      if (campaignMatch && request.method === "PATCH") {
        const id = campaignMatch[1];
        const current = await env.DB.prepare(`SELECT * FROM campaigns WHERE id=?`).bind(id).first();
        if (!current) return error("Campanha não encontrada.",404);
        const body = await request.json();
        const allowedStatus = ["draft","active","paused","finished","archived"];
        const next = {
          name: body.name !== undefined ? String(body.name).trim() : current.name,
          badge: body.badge !== undefined ? String(body.badge) : current.badge,
          title: body.title !== undefined ? String(body.title).trim() : current.title,
          subtitle: body.subtitle !== undefined ? String(body.subtitle) : current.subtitle,
          logo_text: body.logo_text !== undefined ? String(body.logo_text) : current.logo_text,
          primary_color: body.primary_color !== undefined ? String(body.primary_color) : current.primary_color,
          secondary_color: body.secondary_color !== undefined ? String(body.secondary_color) : current.secondary_color,
          banner_url: body.banner_url !== undefined ? String(body.banner_url) : current.banner_url,
          logo_url: body.logo_url !== undefined ? String(body.logo_url) : current.logo_url,
          background_url: body.background_url !== undefined ? String(body.background_url) : current.background_url,
          starts_at: body.starts_at !== undefined ? (body.starts_at || null) : current.starts_at,
          ends_at: body.ends_at !== undefined ? (body.ends_at || null) : current.ends_at,
          status: allowedStatus.includes(body.status) ? body.status : current.status
        };
        if (!next.name || !next.title) return error("Nome e título da campanha são obrigatórios.",422);
        const now = new Date().toISOString();
        if (next.status === "active") {
          await env.DB.prepare(`UPDATE campaigns SET status='archived', updated_at=? WHERE status='active' AND id<>?`).bind(now,id).run();
        }
        await env.DB.prepare(`
          UPDATE campaigns SET name=?,badge=?,title=?,subtitle=?,logo_text=?,primary_color=?,secondary_color=?,
          banner_url=?,logo_url=?,background_url=?,starts_at=?,ends_at=?,status=?,updated_at=? WHERE id=?
        `).bind(next.name,next.badge,next.title,next.subtitle,next.logo_text,next.primary_color,next.secondary_color,next.banner_url,next.logo_url,next.background_url,next.starts_at,next.ends_at,next.status,now,id).run();
        await audit(env,admin,"campaign_updated","campaign",id,{before:current,after:next});
        return json({success:true,campaign:await env.DB.prepare(`SELECT * FROM campaigns WHERE id=?`).bind(id).first()});
      }

      if (campaignMatch && request.method === "DELETE") {
        const id = campaignMatch[1];
        const c = await env.DB.prepare(`SELECT * FROM campaigns WHERE id=?`).bind(id).first();
        if (!c) return error("Campanha não encontrada.",404);
        const counts = await env.DB.batch([
          env.DB.prepare(`SELECT COUNT(*) total FROM referrals WHERE campaign_id=?`).bind(id),
          env.DB.prepare(`SELECT COUNT(*) total FROM enrollments WHERE campaign_id=?`).bind(id),
          env.DB.prepare(`SELECT COUNT(*) total FROM prizes WHERE campaign_id=?`).bind(id),
          env.DB.prepare(`SELECT COUNT(*) total FROM tickets WHERE campaign_id=?`).bind(id),
          env.DB.prepare(`SELECT COUNT(*) total FROM draws WHERE campaign_id=?`).bind(id)
        ]);
        const used = counts.some(x => Number(x.results?.[0]?.total || 0) > 0);
        if (used) return error("Esta campanha já possui histórico e não pode ser excluída. Arquive-a em vez disso.",409);
        await env.DB.prepare(`DELETE FROM campaigns WHERE id=?`).bind(id).run();
        await audit(env,admin,"campaign_deleted","campaign",id,{name:c.name});
        return json({success:true});
      }

      /*
      ==========================================
      ADMIN - PRÊMIOS CRUD
      ==========================================
      */

      if (request.method === "POST" && url.pathname === "/api/admin/prizes") {
        const body = await request.json();
        const name = String(body.name || "").trim();
        const campaignId = String(body.campaign_id || "").trim();
        if (!name) return error("Informe o nome do prêmio.",422);
        const campaign = campaignId
          ? await env.DB.prepare(`SELECT id FROM campaigns WHERE id=?`).bind(campaignId).first()
          : await env.DB.prepare(`SELECT id FROM campaigns WHERE status='active' ORDER BY created_at DESC LIMIT 1`).first();
        if (!campaign) return error("Nenhuma campanha encontrada.",404);
        const id = crypto.randomUUID(), now = new Date().toISOString();
        await env.DB.prepare(`INSERT INTO prizes (id,campaign_id,name,description,icon,image_url,stock,active,display_order,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
          .bind(id,campaign.id,name,String(body.description||""),String(body.icon||"🎁"),String(body.image_url||""),Math.max(0,Number(body.stock??1)),body.active===false||Number(body.active)===0?0:1,Math.max(0,Number(body.display_order??0)),now,now).run();
        await audit(env,admin,"prize_created","prize",id,{name,campaign_id:campaign.id});
        return json({success:true,prize:await env.DB.prepare(`SELECT * FROM prizes WHERE id=?`).bind(id).first()},201);
      }

      const prizeMatch = url.pathname.match(/^\/api\/admin\/prizes\/([^/]+)$/);
      if (prizeMatch && request.method === "PATCH") {
        const id = prizeMatch[1];
        const current = await env.DB.prepare(`SELECT * FROM prizes WHERE id=?`).bind(id).first();
        if (!current) return error("Prêmio não encontrado.",404);
        const body = await request.json();
        const now = new Date().toISOString();
        const next = {
          name: body.name !== undefined ? String(body.name).trim() : current.name,
          description: body.description !== undefined ? String(body.description) : current.description,
          icon: body.icon !== undefined ? String(body.icon) : current.icon,
          image_url: body.image_url !== undefined ? String(body.image_url) : current.image_url,
          stock: body.stock !== undefined ? Math.max(0,Number(body.stock)) : current.stock,
          active: body.active !== undefined ? (Number(body.active)?1:0) : current.active,
          display_order: body.display_order !== undefined ? Math.max(0,Number(body.display_order)) : current.display_order
        };
        if (!next.name) return error("Informe o nome do prêmio.",422);
        await env.DB.prepare(`UPDATE prizes SET name=?,description=?,icon=?,image_url=?,stock=?,active=?,display_order=?,updated_at=? WHERE id=?`)
          .bind(next.name,next.description,next.icon,next.image_url,next.stock,next.active,next.display_order,now,id).run();
        await audit(env,admin,"prize_updated","prize",id,{before:current,after:next});
        return json({success:true,prize:await env.DB.prepare(`SELECT * FROM prizes WHERE id=?`).bind(id).first()});
      }

      if (prizeMatch && request.method === "DELETE") {
        const id = prizeMatch[1];
        const prize = await env.DB.prepare(`SELECT * FROM prizes WHERE id=?`).bind(id).first();
        if (!prize) return error("Prêmio não encontrado.",404);
        const draws = await env.DB.prepare(`SELECT COUNT(*) total FROM draws WHERE prize_id=?`).bind(id).first();
        if (Number(draws?.total||0)>0) return error("Este prêmio já possui sorteios registrados. Desative-o em vez de excluir.",409);
        await env.DB.prepare(`DELETE FROM prizes WHERE id=?`).bind(id).run();
        await audit(env,admin,"prize_deleted","prize",id,{name:prize.name});
        return json({success:true});
      }

      /*
      ==========================================
      ADMIN - EDIÇÃO DE ALUNOS
      ==========================================
      */
      const studentMatch = url.pathname.match(/^\/api\/admin\/students\/([^/]+)$/);
      if (studentMatch && request.method === "PATCH") {
        const id=studentMatch[1];
        const current=await env.DB.prepare(`SELECT * FROM students WHERE id=?`).bind(id).first();
        if(!current)return error("Aluno não encontrado.",404);
        const body=await request.json(); const now=new Date().toISOString();
        const next={name:body.name!==undefined?String(body.name).trim():current.name,whatsapp:body.whatsapp!==undefined?normalizePhone(body.whatsapp):current.whatsapp,phone:body.phone!==undefined?normalizePhone(body.phone):current.phone,email:body.email!==undefined?String(body.email).trim():current.email,active:body.active!==undefined?(Number(body.active)?1:0):current.active};
        if(!next.name||!next.whatsapp)return error("Nome e WhatsApp são obrigatórios.",422);
        const duplicate=await env.DB.prepare(`SELECT id FROM students WHERE whatsapp=? AND id<>? LIMIT 1`).bind(next.whatsapp,id).first();
        if(duplicate)return error("Já existe outro aluno com este WhatsApp.",409);
        await env.DB.prepare(`UPDATE students SET name=?,whatsapp=?,phone=?,email=?,active=?,updated_at=? WHERE id=?`).bind(next.name,next.whatsapp,next.phone,next.email,next.active,now,id).run();
        await audit(env,admin,"student_updated","student",id,{before:current,after:next});
        return json({success:true,student:await env.DB.prepare(`SELECT * FROM students WHERE id=?`).bind(id).first()});
      }

      /*
      ==========================================
      ADMIN - EDIÇÃO / CANCELAMENTO DE INDICAÇÕES
      ==========================================
      */
      const referralMatch = url.pathname.match(/^\/api\/admin\/referrals\/([^/]+)$/);
      if (referralMatch && request.method === "PATCH") {
        const id=referralMatch[1]; const current=await env.DB.prepare(`SELECT * FROM referrals WHERE id=?`).bind(id).first();
        if(!current)return error("Indicação não encontrada.",404);
        const body=await request.json(); const nextStatus=body.status!==undefined?String(body.status):current.status;
        if(!["pending","confirmed","cancelled"].includes(nextStatus))return error("Status de indicação inválido.",422);
        const now=new Date().toISOString();
        const next={lead_name:body.lead_name!==undefined?String(body.lead_name).trim():current.lead_name,lead_whatsapp:body.lead_whatsapp!==undefined?normalizePhone(body.lead_whatsapp):current.lead_whatsapp,lead_phone:body.lead_phone!==undefined?normalizePhone(body.lead_phone):current.lead_phone,lead_email:body.lead_email!==undefined?String(body.lead_email).trim():current.lead_email,status:nextStatus};
        if(!next.lead_name||!next.lead_whatsapp)return error("Nome e WhatsApp do indicado são obrigatórios.",422);
        await env.DB.prepare(`UPDATE referrals SET lead_name=?,lead_whatsapp=?,lead_phone=?,lead_email=?,status=?,cancelled_at=?,cancellation_reason=? WHERE id=?`).bind(next.lead_name,next.lead_whatsapp,next.lead_phone,next.lead_email,next.status,next.status==='cancelled'?now:null,next.status==='cancelled'?String(body.cancellation_reason||"Cancelada pelo administrador"):null,id).run();
        if(next.status==='cancelled'){
          await env.DB.prepare(`UPDATE enrollments SET enrollment_status='cancelled',cancelled_at=?,cancellation_reason=?,updated_at=? WHERE referral_id=? AND enrollment_status NOT IN ('cancelled','refunded')`).bind(now,String(body.cancellation_reason||"Indicação cancelada pelo administrador"),now,id).run();
          await env.DB.prepare(`UPDATE tickets SET status='revoked',revoked_at=?,revoked_reason=? WHERE referral_id=? AND status='available'`).bind(now,"Indicação cancelada",id).run();
        }
        await audit(env,admin,"referral_updated","referral",id,{before:current,after:next});
        return json({success:true,referral:await env.DB.prepare(`SELECT * FROM referrals WHERE id=?`).bind(id).first()});
      }

      /*
      ==========================================
      ADMIN - REVOGAR TICKET
      ==========================================
      */
      const ticketMatch = url.pathname.match(/^\/api\/admin\/tickets\/([^/]+)$/);
      if(ticketMatch && request.method === "PATCH"){
        const id=ticketMatch[1]; const current=await env.DB.prepare(`SELECT * FROM tickets WHERE id=?`).bind(id).first();
        if(!current)return error("Ticket não encontrado.",404);
        if(current.status==='used')return error("Ticket já utilizado não pode ser revogado.",409);
        const body=await request.json(); const reason=String(body.reason||"Revogado pelo administrador").trim(); const now=new Date().toISOString();
        await env.DB.prepare(`UPDATE tickets SET status='revoked',revoked_at=?,revoked_reason=? WHERE id=? AND status='available'`).bind(now,reason,id).run();
        await audit(env,admin,"ticket_revoked","ticket",id,{reason,code:current.code});
        return json({success:true});
      }

      /*
      ==========================================
      ADMIN - LIBERAÇÃO ANTECIPADA
      ==========================================
      */
      const earlyMatch=url.pathname.match(/^\/api\/admin\/enrollments\/([^/]+)\/confirm-early$/);
      if(earlyMatch && request.method==='POST'){
        const enrollmentId=earlyMatch[1]; const body=await request.json(); const reason=String(body.reason||"").trim();
        if(!reason)return error("Informe o motivo da liberação antecipada.",422);
        const enrollment=await env.DB.prepare(`SELECT e.*,r.student_id FROM enrollments e JOIN referrals r ON r.id=e.referral_id WHERE e.id=? LIMIT 1`).bind(enrollmentId).first();
        if(!enrollment)return error("Matrícula não encontrada.",404);
        if(['cancelled','refunded'].includes(enrollment.enrollment_status))return error("Matrícula cancelada ou reembolsada.",409);
        const existing=await env.DB.prepare(`SELECT * FROM tickets WHERE referral_id=? LIMIT 1`).bind(enrollment.referral_id).first();
        if(existing)return error("Esta indicação já possui ticket.",409);
        const code=await uniqueTicket(env), now=new Date().toISOString(), ticketId=crypto.randomUUID();
        await env.DB.batch([
          env.DB.prepare(`UPDATE enrollments SET enrollment_status='confirmed',confirmed_at=?,confirmed_by=?,updated_at=? WHERE id=?`).bind(now,admin.id,now,enrollmentId),
          env.DB.prepare(`UPDATE referrals SET status='confirmed',confirmed_at=?,confirmed_by=? WHERE id=?`).bind(now,admin.id,enrollment.referral_id),
          env.DB.prepare(`INSERT INTO tickets (id,campaign_id,student_id,referral_id,code,status,created_at) VALUES (?,?,?,?,?,'available',?)`).bind(ticketId,enrollment.campaign_id,enrollment.student_id,enrollment.referral_id,code,now)
        ]);
        await audit(env,admin,"early_ticket_release","enrollment",enrollmentId,{referral_id:enrollment.referral_id,ticket_code:code,reason,override_7_days:true,eligible_at:enrollment.eligible_at});
        return json({success:true,message:"Ticket liberado antecipadamente.",ticket:{id:ticketId,code,status:"available"}});
      }

      /*
      ==========================================
      ADMIN - RANKING
      ==========================================
      */
      if(request.method==='GET' && url.pathname==='/api/admin/ranking'){
        const result=await env.DB.prepare(`
          SELECT s.id,s.name,s.whatsapp,
            COUNT(DISTINCT r.id) referrals,
            COUNT(DISTINCT CASE WHEN r.status='confirmed' THEN r.id END) confirmed_referrals,
            COUNT(DISTINCT t.id) tickets,
            COUNT(DISTINCT d.id) draws
          FROM students s
          LEFT JOIN referrals r ON r.student_id=s.id
          LEFT JOIN tickets t ON t.student_id=s.id
          LEFT JOIN draws d ON d.student_id=s.id
          GROUP BY s.id
          ORDER BY confirmed_referrals DESC, referrals DESC, tickets DESC, s.name ASC
          LIMIT 100
        `).all();
        return json({success:true,ranking:result.results||[]});
      }

      /*
      ==========================================
      ADMIN - HISTÓRICO
      ==========================================
      */
      if(request.method==='GET' && url.pathname==='/api/admin/history'){
        const result=await env.DB.prepare(`
          SELECT a.id,a.action,a.entity_type,a.entity_id,a.details_json,a.created_at,
                 COALESCE(ad.name,'Sistema') admin_name
          FROM audit_logs a
          LEFT JOIN admins ad ON ad.id=a.admin_id
          ORDER BY a.created_at DESC
          LIMIT 500
        `).all();
        return json({success:true,history:result.results||[]});
      }

      /*
      ==========================================
      ADMIN - EXPORTAÇÕES CSV
      ==========================================
      */
      if(request.method==='GET' && url.pathname.startsWith('/api/admin/export/')){
        const type=url.pathname.split('/').pop(); let rows=[],columns=[];
        if(type==='students'){
          rows=(await env.DB.prepare(`SELECT * FROM students ORDER BY created_at DESC`).all()).results||[];
          columns=[{key:'name',label:'Nome'},{key:'whatsapp',label:'WhatsApp'},{key:'phone',label:'Telefone'},{key:'email',label:'E-mail'},{key:'active',label:'Ativo'},{key:'created_at',label:'Criado em'}];
        } else if(type==='referrals'){
          rows=(await env.DB.prepare(`SELECT r.*,s.name student_name,s.whatsapp student_whatsapp FROM referrals r JOIN students s ON s.id=r.student_id ORDER BY r.created_at DESC`).all()).results||[];
          columns=[{key:'lead_name',label:'Lead'},{key:'lead_whatsapp',label:'WhatsApp'},{key:'lead_email',label:'E-mail'},{key:'student_name',label:'Indicador'},{key:'student_whatsapp',label:'WhatsApp indicador'},{key:'status',label:'Status'},{key:'created_at',label:'Criado em'},{key:'eligible_at',label:'Elegível em'}];
        } else if(type==='enrollments'){
          rows=(await env.DB.prepare(`SELECT e.*,s.name indicator_name,s.whatsapp indicator_whatsapp FROM enrollments e JOIN referrals r ON r.id=e.referral_id JOIN students s ON s.id=r.student_id ORDER BY e.created_at DESC`).all()).results||[];
          columns=[{key:'lead_name',label:'Lead'},{key:'indicator_name',label:'Indicador'},{key:'indicator_whatsapp',label:'WhatsApp indicador'},{key:'enrollment_status',label:'Status'},{key:'paid_at',label:'Pago em'},{key:'eligible_at',label:'Elegível em'},{key:'confirmed_at',label:'Confirmado em'}];
        } else if(type==='tickets'){
          rows=(await env.DB.prepare(`SELECT t.*,s.name student_name,s.whatsapp student_whatsapp FROM tickets t JOIN students s ON s.id=t.student_id ORDER BY t.created_at DESC`).all()).results||[];
          columns=[{key:'code',label:'Ticket'},{key:'student_name',label:'Aluno'},{key:'student_whatsapp',label:'WhatsApp'},{key:'status',label:'Status'},{key:'created_at',label:'Criado em'},{key:'used_at',label:'Usado em'},{key:'revoked_reason',label:'Motivo revogação'}];
        } else if(type==='draws'){
          rows=(await env.DB.prepare(`SELECT d.*,t.code ticket_code,s.name student_name,p.name prize_name FROM draws d JOIN tickets t ON t.id=d.ticket_id JOIN students s ON s.id=d.student_id JOIN prizes p ON p.id=d.prize_id ORDER BY d.drawn_at DESC`).all()).results||[];
          columns=[{key:'drawn_at',label:'Data'},{key:'ticket_code',label:'Ticket'},{key:'student_name',label:'Aluno'},{key:'prize_name',label:'Prêmio'}];
        } else return error('Tipo de exportação inválido.',404);
        return csvResponse(rows,columns);
      }

      /*
      ==========================================
      ADMIN - DASHBOARD
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/admin/dashboard"
      ) {

        const campaign =
          await env.DB
            .prepare(`
              SELECT *
              FROM campaigns
              ORDER BY created_at DESC
              LIMIT 1
            `)
            .first();


        const campaignId =
          campaign?.id || "";


        const results =
          await env.DB.batch([

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM students
            `),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM referrals
              WHERE campaign_id = ?
            `)
            .bind(
              campaignId
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM enrollments
              WHERE campaign_id = ?
            `)
            .bind(
              campaignId
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM enrollments
              WHERE campaign_id = ?
                AND enrollment_status =
                  'paid_waiting'
            `)
            .bind(
              campaignId
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM tickets
              WHERE campaign_id = ?
                AND status = 'available'
            `)
            .bind(
              campaignId
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM prizes
              WHERE campaign_id = ?
                AND active = 1
            `)
            .bind(
              campaignId
            ),

            env.DB.prepare(`
              SELECT COUNT(*) total
              FROM draws
              WHERE campaign_id = ?
            `)
            .bind(
              campaignId
            )

          ]);


        return json({

          success: true,

          campaign,

          dashboard: {

            students:
              Number(
                results[0]
                  .results[0]
                  .total
              ),

            referrals:
              Number(
                results[1]
                  .results[0]
                  .total
              ),

            enrollments:
              Number(
                results[2]
                  .results[0]
                  .total
              ),

            waiting_7_days:
              Number(
                results[3]
                  .results[0]
                  .total
              ),

            available_tickets:
              Number(
                results[4]
                  .results[0]
                  .total
              ),

            prizes:
              Number(
                results[5]
                  .results[0]
                  .total
              ),

            draws:
              Number(
                results[6]
                  .results[0]
                  .total
              )

          }

        });
      }


      /*
      ==========================================
      ADMIN - INDICAÇÕES
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/admin/referrals"
      ) {

        const result =
          await env.DB
            .prepare(`
              SELECT
                r.*,
                s.name AS student_name,
                s.whatsapp AS student_whatsapp
              FROM referrals r
              JOIN students s
                ON s.id = r.student_id
              ORDER BY r.created_at DESC
              LIMIT 500
            `)
            .all();


        return json({

          success: true,

          referrals:
            result.results || []

        });
      }


      /*
      ==========================================
      ADMIN - ALUNOS
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/admin/students"
      ) {

        const result =
          await env.DB
            .prepare(`
              SELECT
                s.*,
                COUNT(DISTINCT r.id)
                  AS referrals,
                COUNT(DISTINCT t.id)
                  AS tickets
              FROM students s

              LEFT JOIN referrals r
                ON r.student_id = s.id

              LEFT JOIN tickets t
                ON t.student_id = s.id

              GROUP BY s.id

              ORDER BY s.created_at DESC

              LIMIT 500
            `)
            .all();


        return json({

          success: true,

          students:
            result.results || []

        });
      }


      /*
      ==========================================
      ADMIN - MATRÍCULAS
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/admin/enrollments"
      ) {

        const result =
          await env.DB
            .prepare(`
              SELECT
                e.*,
                r.lead_whatsapp,
                s.name AS indicator_name,
                s.whatsapp AS indicator_whatsapp
              FROM enrollments e

              JOIN referrals r
                ON r.id = e.referral_id

              JOIN students s
                ON s.id = r.student_id

              ORDER BY e.created_at DESC

              LIMIT 500
            `)
            .all();


        return json({

          success: true,

          enrollments:
            result.results || []

        });
      }


      /*
      ==========================================
      ADMIN - TICKETS
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/admin/tickets"
      ) {

        const result =
          await env.DB
            .prepare(`
              SELECT
                t.*,
                s.name AS student_name,
                s.whatsapp AS student_whatsapp
              FROM tickets t

              JOIN students s
                ON s.id = t.student_id

              ORDER BY t.created_at DESC

              LIMIT 500
            `)
            .all();


        return json({

          success: true,

          tickets:
            result.results || []

        });
      }


      /*
      ==========================================
      ADMIN - PRÊMIOS
      ==========================================
      */

      if (
        request.method === "GET" &&
        url.pathname ===
          "/api/admin/prizes"
      ) {

        const result =
          await env.DB
            .prepare(`
              SELECT *
              FROM prizes
              ORDER BY
                display_order ASC,
                created_at DESC
            `)
            .all();


        return json({

          success: true,

          prizes:
            result.results || []

        });
      }


      /*
      ==========================================
      ADMIN - REGISTRAR MATRÍCULA
      ==========================================
      */

      if (
        request.method === "POST" &&
        url.pathname ===
          "/api/admin/enrollments"
      ) {

        const body =
          await request.json();


        const referralId =
          String(
            body.referral_id || ""
          ).trim();


        if (!referralId) {

          return error(
            "Informe a indicação.",
            422
          );
        }


        /*
        ----------------------------------------
        BUSCA INDICAÇÃO
        ----------------------------------------
        */

        const referral =
          await env.DB
            .prepare(`
              SELECT
                r.*,
                c.name AS campaign_name
              FROM referrals r
              JOIN campaigns c
                ON c.id = r.campaign_id
              WHERE r.id = ?
              LIMIT 1
            `)
            .bind(
              referralId
            )
            .first();


        if (!referral) {

          return error(
            "Indicação não encontrada.",
            404
          );
        }


        /*
        ----------------------------------------
        NÃO PERMITE CANCELADA
        ----------------------------------------
        */

        if (
          referral.status ===
          "cancelled"
        ) {

          return error(
            "Esta indicação está cancelada.",
            409
          );
        }


        /*
        ----------------------------------------
        EVITA DUPLICIDADE
        ----------------------------------------
        */

        const existing =
          await env.DB
            .prepare(`
              SELECT *
              FROM enrollments
              WHERE referral_id = ?
              LIMIT 1
            `)
            .bind(
              referralId
            )
            .first();


        if (existing) {

          return error(
            "Esta indicação já possui uma matrícula registrada.",
            409
          );
        }


        /*
        ----------------------------------------
        DATA DO PAGAMENTO
        ----------------------------------------
        */

        const paidAt =
          body.paid_at
            ? new Date(
                body.paid_at
              )
            : new Date();


        if (
          Number.isNaN(
            paidAt.getTime()
          )
        ) {

          return error(
            "Data de pagamento inválida.",
            422
          );
        }


        /*
        ----------------------------------------
        7 DIAS
        ----------------------------------------
        */

        const eligibleAt =
          new Date(
            paidAt.getTime() +
            7 *
            24 *
            60 *
            60 *
            1000
          );


        const enrollmentId =
          crypto.randomUUID();


        const now =
          new Date().toISOString();


        /*
        ----------------------------------------
        GRAVA MATRÍCULA
        ----------------------------------------
        */

        await env.DB
          .prepare(`
            INSERT INTO enrollments (
              id,
              referral_id,
              campaign_id,
              lead_name,
              enrollment_status,
              paid_at,
              eligible_at,
              created_at,
              updated_at
            )
            VALUES (
              ?, ?, ?, ?, 'paid_waiting',
              ?, ?, ?, ?
            )
          `)
          .bind(
            enrollmentId,
            referral.id,
            referral.campaign_id,
            referral.lead_name,
            paidAt.toISOString(),
            eligibleAt.toISOString(),
            now,
            now
          )
          .run();


        /*
        ----------------------------------------
        AUDITORIA
        ----------------------------------------
        */

        await audit(
          env,
          admin,
          "create_enrollment",
          "enrollment",
          enrollmentId,
          {

            referral_id:
              referral.id,

            lead_name:
              referral.lead_name,

            paid_at:
              paidAt.toISOString(),

            eligible_at:
              eligibleAt.toISOString()

          }
        );


        return json({

          success: true,

          message:
            "Matrícula registrada. O período de segurança de 7 dias foi iniciado.",

          enrollment: {

            id:
              enrollmentId,

            referral_id:
              referral.id,

            campaign_id:
              referral.campaign_id,

            lead_name:
              referral.lead_name,

            enrollment_status:
              "paid_waiting",

            paid_at:
              paidAt.toISOString(),

            eligible_at:
              eligibleAt.toISOString()

          }

        }, 201);
      }


      /*
      ==========================================
      ADMIN - CONFIRMAR MATRÍCULA
      ==========================================
      */

      const confirmMatch =
        url.pathname.match(
          /^\/api\/admin\/enrollments\/([^/]+)\/confirm$/
        );


      if (
        request.method === "POST" &&
        confirmMatch
      ) {

        const enrollmentId =
          confirmMatch[1];


        /*
        ----------------------------------------
        BUSCA MATRÍCULA
        ----------------------------------------
        */

        const enrollment =
          await env.DB
            .prepare(`
              SELECT
                e.*,
                r.student_id
              FROM enrollments e
              JOIN referrals r
                ON r.id = e.referral_id
              WHERE e.id = ?
              LIMIT 1
            `)
            .bind(
              enrollmentId
            )
            .first();


        if (!enrollment) {

          return error(
            "Matrícula não encontrada.",
            404
          );
        }


        /*
        ----------------------------------------
        JÁ CONFIRMADA
        ----------------------------------------
        */

        if (
          enrollment.enrollment_status ===
          "confirmed"
        ) {

          const ticket =
            await env.DB
              .prepare(`
                SELECT *
                FROM tickets
                WHERE referral_id = ?
                LIMIT 1
              `)
              .bind(
                enrollment.referral_id
              )
              .first();


          return json({

            success: true,

            message:
              "Matrícula já confirmada.",

            ticket

          });
        }


        /*
        ----------------------------------------
        CANCELADA / REEMBOLSADA
        ----------------------------------------
        */

        if (
          enrollment.enrollment_status ===
            "cancelled" ||
          enrollment.enrollment_status ===
            "refunded"
        ) {

          return error(
            "Matrícula cancelada ou reembolsada.",
            409
          );
        }


        /*
        ----------------------------------------
        VERIFICA 7 DIAS
        ----------------------------------------
        */

        const eligible =
          new Date(
            enrollment.eligible_at
          ).getTime();


        if (
          eligible > Date.now()
        ) {

          return error(
            "Ainda não completou os 7 dias.",
            409
          );
        }


        /*
        ----------------------------------------
        EVITA DUPLICAÇÃO
        ----------------------------------------
        */

        const existing =
          await env.DB
            .prepare(`
              SELECT id
              FROM tickets
              WHERE referral_id = ?
              LIMIT 1
            `)
            .bind(
              enrollment.referral_id
            )
            .first();


        if (existing) {

          return error(
            "Esta indicação já possui ticket.",
            409
          );
        }


        /*
        ----------------------------------------
        GERA TICKET
        ----------------------------------------
        */

        const code =
          await uniqueTicket(
            env
          );


        const now =
          new Date().toISOString();


        const ticketId =
          crypto.randomUUID();


        /*
        ----------------------------------------
        GRAVA TUDO
        ----------------------------------------
        */

        await env.DB.batch([

          env.DB.prepare(`
            UPDATE enrollments
            SET
              enrollment_status = 'confirmed',
              confirmed_at = ?,
              confirmed_by = ?,
              updated_at = ?
            WHERE id = ?
          `)
          .bind(
            now,
            admin.id,
            now,
            enrollmentId
          ),

          env.DB.prepare(`
            UPDATE referrals
            SET
              status = 'confirmed',
              confirmed_at = ?,
              confirmed_by = ?
            WHERE id = ?
          `)
          .bind(
            now,
            admin.id,
            enrollment.referral_id
          ),

          env.DB.prepare(`
            INSERT INTO tickets (
              id,
              campaign_id,
              student_id,
              referral_id,
              code,
              status,
              created_at
            )
            VALUES (
              ?, ?, ?, ?, ?,
              'available', ?
            )
          `)
          .bind(
            ticketId,
            enrollment.campaign_id,
            enrollment.student_id,
            enrollment.referral_id,
            code,
            now
          )

        ]);


        await audit(
          env,
          admin,
          "confirm_enrollment",
          "enrollment",
          enrollmentId,
          {

            referral_id:
              enrollment.referral_id,

            ticket_code:
              code

          }
        );


        return json({

          success: true,

          message:
            "Matrícula confirmada e ticket gerado.",

          ticket: {

            id:
              ticketId,

            code,

            status:
              "available"

          }

        });
      }


      /*
      ==========================================
      ALUNO - REALIZAR SORTEIO
      ==========================================
      */

      if (
        request.method === "POST" &&
        url.pathname ===
          "/api/student/draw"
      ) {

        const student =
          await getStudent(
            request,
            env
          );


        if (!student) {

          return error(
            "Não autenticado.",
            401
          );
        }


        const body =
          await request.json();


        const ticketCodeInput =
          String(
            body.ticket_code ||
            body.ticketCode ||
            ""
          )
            .trim()
            .toUpperCase();


        if (!ticketCodeInput) {

          return error(
            "Informe o código do ticket.",
            422
          );
        }


        /*
        ----------------------------------------
        BUSCA CAMPANHA ATIVA
        ----------------------------------------
        */

        const campaign =
          await env.DB
            .prepare(`
              SELECT *
              FROM campaigns
              WHERE status = 'active'
              ORDER BY created_at DESC
              LIMIT 1
            `)
            .first();


        if (!campaign) {

          return error(
            "Nenhuma campanha ativa.",
            404
          );
        }


        /*
        ----------------------------------------
        BUSCA TICKET DO PRÓPRIO ALUNO
        ----------------------------------------
        */

        const ticket =
          await env.DB
            .prepare(`
              SELECT
                t.id,
                t.campaign_id,
                t.student_id,
                t.referral_id,
                t.code,
                t.status
              FROM tickets t
              WHERE t.code = ?
                AND t.student_id = ?
                AND t.campaign_id = ?
              LIMIT 1
            `)
            .bind(
              ticketCodeInput,
              student.id,
              campaign.id
            )
            .first();


        if (!ticket) {

          return error(
            "Ticket não encontrado ou não pertence a você.",
            404
          );
        }


        if (
          ticket.status !==
          "available"
        ) {

          if (
            ticket.status ===
            "used"
          ) {

            return error(
              "Este ticket já foi utilizado.",
              409
            );
          }


          return error(
            "Este ticket não está disponível.",
            409
          );
        }


        /*
        ----------------------------------------
        BUSCA PRÊMIOS COM ESTOQUE
        ----------------------------------------
        */

        const prizeResult =
          await env.DB
            .prepare(`
              SELECT
                id,
                name,
                description,
                icon,
                image_url,
                stock
              FROM prizes
              WHERE campaign_id = ?
                AND active = 1
                AND stock > 0
              ORDER BY display_order ASC, created_at ASC
            `)
            .bind(
              campaign.id
            )
            .all();


        const prizes =
          prizeResult.results || [];


        if (!prizes.length) {

          return error(
            "Nenhum prêmio disponível no momento.",
            409
          );
        }


        /*
        ----------------------------------------
        ESCOLHA ALEATÓRIA NO SERVIDOR
        ----------------------------------------
        */

        const randomBytes =
          new Uint32Array(1);

        crypto.getRandomValues(
          randomBytes
        );


        const prizeIndex =
          randomBytes[0] %
          prizes.length;


        const prize =
          prizes[prizeIndex];


        /*
        ----------------------------------------
        RESERVA O TICKET
        ----------------------------------------
        */

        const now =
          new Date().toISOString();


        const ticketUpdate =
          await env.DB
            .prepare(`
              UPDATE tickets
              SET
                status = 'used',
                used_at = ?
              WHERE id = ?
                AND student_id = ?
                AND campaign_id = ?
                AND status = 'available'
            `)
            .bind(
              now,
              ticket.id,
              student.id,
              campaign.id
            )
            .run();


        if (
          !ticketUpdate.meta ||
          ticketUpdate.meta.changes !== 1
        ) {

          return error(
            "Este ticket já foi utilizado ou não está mais disponível.",
            409
          );
        }


        /*
        ----------------------------------------
        RESERVA 1 UNIDADE DO PRÊMIO
        ----------------------------------------
        */

        const prizeUpdate =
          await env.DB
            .prepare(`
              UPDATE prizes
              SET
                stock = stock - 1,
                updated_at = ?
              WHERE id = ?
                AND campaign_id = ?
                AND active = 1
                AND stock > 0
            `)
            .bind(
              now,
              prize.id,
              campaign.id
            )
            .run();


        if (
          !prizeUpdate.meta ||
          prizeUpdate.meta.changes !== 1
        ) {

          await env.DB
            .prepare(`
              UPDATE tickets
              SET
                status = 'available',
                used_at = NULL
              WHERE id = ?
                AND student_id = ?
                AND status = 'used'
            `)
            .bind(
              ticket.id,
              student.id
            )
            .run();


          return error(
            "O prêmio selecionado acabou de ser reservado. Tente novamente.",
            409
          );
        }


        /*
        ----------------------------------------
        REGISTRA O SORTEIO
        ----------------------------------------
        */

        const drawId =
          crypto.randomUUID();


        try {

          await env.DB
            .prepare(`
              INSERT INTO draws (
                id,
                campaign_id,
                prize_id,
                ticket_id,
                student_id,
                drawn_at
              )
              VALUES (?, ?, ?, ?, ?, ?)
            `)
            .bind(
              drawId,
              campaign.id,
              prize.id,
              ticket.id,
              student.id,
              now
            )
            .run();

        } catch (drawError) {

          console.error(
            "Erro ao registrar sorteio:",
            drawError
          );


          await env.DB
            .prepare(`
              UPDATE prizes
              SET
                stock = stock + 1,
                updated_at = ?
              WHERE id = ?
            `)
            .bind(
              now,
              prize.id
            )
            .run();


          await env.DB
            .prepare(`
              UPDATE tickets
              SET
                status = 'available',
                used_at = NULL
              WHERE id = ?
                AND student_id = ?
                AND status = 'used'
            `)
            .bind(
              ticket.id,
              student.id
            )
            .run();


          throw drawError;
        }


        /*
        ----------------------------------------
        AUDITORIA
        ----------------------------------------
        */

        await audit(
          env,
          null,
          "student_draw",
          "draw",
          drawId,
          {
            campaign_id:
              campaign.id,

            student_id:
              student.id,

            ticket_id:
              ticket.id,

            ticket_code:
              ticket.code,

            prize_id:
              prize.id,

            prize_name:
              prize.name
          }
        );


        /*
        ----------------------------------------
        RESULTADO
        ----------------------------------------
        */

        return json({

          success: true,

          message:
            "Parabéns! Você ganhou!",

          draw: {

            id:
              drawId,

            drawn_at:
              now,

            ticket_code:
              ticket.code,

            prize: {

              id:
                prize.id,

              name:
                prize.name,

              description:
                prize.description || "",

              icon:
                prize.icon || "🎁",

              image_url:
                prize.image_url || ""
            }
          }

        });
      }


      /*
      ==========================================
      ROTA NÃO ENCONTRADA
      ==========================================
      */

      return error(
        "Rota não encontrada.",
        404
      );


    } catch (e) {

      console.error(e);


      return error(
        "Erro interno da API.",
        500
      );
    }
  }
};