const API = (window.INDICA_CONFIG?.apiBaseUrl || "").replace(/\/$/, "");

const STUDENT_TOKEN_KEY = "indica_student_token";
const STUDENT_KEY = "indica_current_student";

function apiUrl(path) {
  return `${API}${path}`;
}

async function apiFetch(path, options = {}) {
  const token = localStorage.getItem(STUDENT_TOKEN_KEY);

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(apiUrl(path), {
    ...options,
    headers
  });

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {
      success: false,
      error: "Resposta inválida da API."
    };
  }

  if (!response.ok || data.success === false) {
    const err = new Error(
      data.error || "Não foi possível concluir a operação."
    );

    err.status = response.status;
    throw err;
  }

  return data;
}


function toast(msg) {
  const t = document.getElementById("toast");

  if (!t) {
    alert(msg);
    return;
  }

  t.textContent = msg;
  t.classList.add("show");

  setTimeout(() => {
    t.classList.remove("show");
  }, 2800);
}


function fmtDate(value) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return date.toLocaleDateString("pt-BR");
}


function fmtDateTime(value) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return date.toLocaleString("pt-BR");
}


function currentStudent() {
  try {
    return JSON.parse(
      localStorage.getItem(STUDENT_KEY) || "null"
    );
  } catch {
    return null;
  }
}


function setStudent(student) {
  localStorage.setItem(
    STUDENT_KEY,
    JSON.stringify(student)
  );
}


function clearStudentSession() {
  localStorage.removeItem(STUDENT_TOKEN_KEY);
  localStorage.removeItem(STUDENT_KEY);
}


/*
==================================================
PÁGINA PÚBLICA
==================================================
*/

async function initPublic() {

  /*
  ------------------------------------------
  CAMPANHA
  ------------------------------------------
  */

  try {

    const campaignResponse =
      await apiFetch("/api/campaign");

    const campaign =
      campaignResponse.campaign;

    if (campaign) {

      document.documentElement.style.setProperty(
        "--primary",
        campaign.primary_color || "#6d28d9"
      );

      document.documentElement.style.setProperty(
        "--primary2",
        campaign.secondary_color || "#8b5cf6"
      );

      const set = (id, value) => {
        const element =
          document.getElementById(id);

        if (element) {
          element.innerHTML = value ?? "";
        }
      };

      set(
        "brandName",
        (campaign.logo_text || "Indica+")
          .replace(
            "+",
            "<span>+</span>"
          )
      );

      set(
        "campaignBadge",
        campaign.badge ||
        "CAMPANHA ATIVA"
      );

      set(
        "campaignTitle",
        String(
          campaign.title ||
          "Indique. Ganhe. Evolua."
        ).replace(
          /Evolua\./i,
          "<span>Evolua.</span>"
        )
      );

      set(
        "campaignSubtitle",
        campaign.subtitle || ""
      );
    }

  } catch (error) {

    console.error(
      "Erro ao carregar campanha:",
      error
    );
  }


  /*
  ------------------------------------------
  ESTATÍSTICAS
  ------------------------------------------
  */

  try {

    const statsResponse =
      await apiFetch("/api/stats");

    const stats =
      statsResponse.stats || {};

    const set = (id, value) => {

      const element =
        document.getElementById(id);

      if (element) {
        element.textContent =
          value ?? 0;
      }
    };

    set(
      "heroTickets",
      stats.tickets
    );

    set(
      "heroPrizes",
      stats.prizes
    );

    set(
      "heroIndications",
      stats.referrals
    );

  } catch (error) {

    console.error(
      "Erro ao carregar estatísticas:",
      error
    );
  }


  /*
  ------------------------------------------
  LOGIN
  ------------------------------------------
  */

  const form =
    document.getElementById("loginForm");

  if (form) {

    form.onsubmit = async event => {

      event.preventDefault();

      const input =
        document.getElementById(
          "loginPhone"
        );

      const phone =
        input?.value?.trim() || "";

      if (!phone) {

        toast(
          "Informe seu WhatsApp."
        );

        return;
      }


      /*
      ----------------------------------------
      TENTA RECUPERAR NOME ANTIGO
      ----------------------------------------
      */

      const oldStudent =
        currentStudent();

      const oldName =
        oldStudent?.name || "";


      try {

        const response =
          await apiFetch(
            "/api/student/login",
            {
              method: "POST",

              body: JSON.stringify({
                name:
                  oldName || "Aluno",

                whatsapp:
                  phone
              })
            }
          );


        /*
        --------------------------------------
        SALVA APENAS SESSÃO
        --------------------------------------
        */

        localStorage.setItem(
          STUDENT_TOKEN_KEY,
          response.token
        );

        setStudent(
          response.student
        );


        location.href =
          "aluno.html";

      } catch (error) {

        console.error(error);

        toast(
          error.message ||
          "Não foi possível entrar."
        );
      }
    };
  }
}


/*
==================================================
PÁGINA DO ALUNO
==================================================
*/

async function initStudent() {

  const token =
    localStorage.getItem(
      STUDENT_TOKEN_KEY
    );

  if (!token) {

    location.href =
      "index.html#acessar";

    return;
  }


  /*
  ------------------------------------------
  VALIDAR SESSÃO
  ------------------------------------------
  */

  try {

    const me =
      await apiFetch(
        "/api/student/me"
      );

    setStudent(
      me.student
    );

  } catch (error) {

    console.error(error);

    clearStudentSession();

    location.href =
      "index.html#acessar";

    return;
  }


  /*
  ------------------------------------------
  BOTÃO SAIR
  ------------------------------------------
  */

  const logoutBtn =
    document.getElementById(
      "logoutBtn"
    );

  if (logoutBtn) {

    logoutBtn.onclick =
      async () => {

        try {

          await apiFetch(
            "/api/student/logout",
            {
              method: "POST"
            }
          );

        } catch (error) {

          console.error(error);

        } finally {

          clearStudentSession();

          location.href =
            "index.html";
        }
      };
  }


  /*
  ------------------------------------------
  MODAL NOVA INDICAÇÃO
  ------------------------------------------
  */

  const openReferral =
    document.getElementById(
      "openReferral"
    );

  if (openReferral) {

    openReferral.onclick = () => {

      const modal =
        document.getElementById(
          "referralModal"
        );

      if (modal) {
        modal.classList.add("open");
      }
    };
  }


  document
    .querySelectorAll("[data-close]")
    .forEach(button => {

      button.onclick = () => {

        const modal =
          button.closest(".modal");

        if (modal) {
          modal.classList.remove(
            "open"
          );
        }
      };
    });


  /*
  ------------------------------------------
  FORMULÁRIO DE INDICAÇÃO
  ------------------------------------------
  */

  const referralForm =
    document.getElementById(
      "referralForm"
    );

  if (referralForm) {

    referralForm.onsubmit =
      async event => {

        event.preventDefault();

        const name =
          document
            .getElementById("refName")
            ?.value
            .trim() || "";

        const whatsapp =
          document
            .getElementById("refPhone")
            ?.value
            .trim() || "";

        const email =
          document
            .getElementById("refEmail")
            ?.value
            .trim() || "";


        if (!name) {

          toast(
            "Informe o nome do indicado."
          );

          return;
        }

        if (!whatsapp) {

          toast(
            "Informe o WhatsApp do indicado."
          );

          return;
        }


        const submitButton =
          referralForm.querySelector(
            "button[type='submit']"
          ) ||
          referralForm.querySelector(
            "button"
          );

        const originalText =
          submitButton?.textContent;


        try {

          if (submitButton) {

            submitButton.disabled =
              true;

            submitButton.textContent =
              "Registrando...";
          }


          await apiFetch(
            "/api/student/referrals",
            {
              method: "POST",

              body: JSON.stringify({
                name,
                whatsapp,
                email
              })
            }
          );


          referralForm.reset();


          const modal =
            document.getElementById(
              "referralModal"
            );

          if (modal) {
            modal.classList.remove(
              "open"
            );
          }


          toast(
            "Indicação registrada com sucesso! 🎉"
          );


          await renderStudent();

        } catch (error) {

          console.error(error);

          toast(
            error.message ||
            "Não foi possível registrar a indicação."
          );

        } finally {

          if (submitButton) {

            submitButton.disabled =
              false;

            submitButton.textContent =
              originalText ||
              "Registrar indicação";
          }
        }
      };
  }


  /*
  ------------------------------------------
  SORTEIO
  ------------------------------------------
  */

  const drawForm =
    document.getElementById(
      "drawForm"
    );

  if (drawForm) {

    drawForm.onsubmit =
      event => {

        event.preventDefault();

        const result =
          document.getElementById(
            "drawResult"
          );

        if (result) {

          result.innerHTML = `
            <div class="win-card">
              <div class="big">🎰</div>
              <b>Sorteio em preparação</b>
              <p>
                O sorteio será realizado
                pelo sistema oficial da campanha.
              </p>
            </div>
          `;
        }
      };
  }


  /*
  ------------------------------------------
  CARREGA DADOS
  ------------------------------------------
  */

  await renderStudent();
}


/*
==================================================
RENDERIZA ÁREA DO ALUNO
==================================================
*/

async function renderStudent() {

  try {

    const response =
      await apiFetch(
        "/api/student/dashboard"
      );

    const student =
      response.student;

    const referrals =
      response.referrals || [];

    const tickets =
      response.tickets || [];

    const wins =
      response.wins || [];


    /*
    ------------------------------------------
    DADOS DO ALUNO
    ------------------------------------------
    */

    setStudent(student);


    const studentName =
      document.getElementById(
        "studentName"
      );

    if (studentName) {
      studentName.textContent =
        student.name || "Aluno";
    }


    const helloName =
      document.getElementById(
        "helloName"
      );

    if (helloName) {

      helloName.textContent =
        String(
          student.name || "Aluno"
        )
        .split(" ")[0];
    }


    /*
    ------------------------------------------
    MÉTRICAS
    ------------------------------------------
    */

    const availableTickets =
      tickets.filter(
        ticket =>
          ticket.status === "available"
      );


    const confirmed =
      referrals.filter(
        referral =>
          referral.status === "confirmed"
      );


    const set = (
      id,
      value
    ) => {

      const element =
        document.getElementById(id);

      if (element) {
        element.textContent =
          value;
      }
    };


    set(
      "mIndications",
      referrals.length
    );

    set(
      "mConfirmed",
      confirmed.length
    );

    set(
      "mTickets",
      availableTickets.length
    );

    set(
      "mWins",
      wins.length
    );

    set(
      "ticketCount",
      `${availableTickets.length} disponíveis`
    );


    /*
    ------------------------------------------
    TICKETS
    ------------------------------------------
    */

    const ticketList =
      document.getElementById(
        "ticketList"
      );

    if (ticketList) {

      if (!availableTickets.length) {

        ticketList.innerHTML = `
          <div class="empty">
            Você ainda não tem tickets disponíveis.
            Continue indicando! 🚀
          </div>
        `;

      } else {

        ticketList.innerHTML =
          availableTickets
            .map(ticket => `
              <div class="ticket-row">

                <div>

                  <code>
                    ${escapeHtml(
                      ticket.code
                    )}
                  </code>

                  <small>
                    Ticket disponível
                  </small>

                </div>

                <span class="status confirmed">
                  DISPONÍVEL
                </span>

              </div>
            `)
            .join("");
      }
    }


    /*
    ------------------------------------------
    INDICAÇÕES
    ------------------------------------------
    */

    const referralList =
      document.getElementById(
        "referralList"
      );

    if (referralList) {

      if (!referrals.length) {

        referralList.innerHTML = `
          <div class="empty">
            Nenhuma indicação ainda.
          </div>
        `;

      } else {

        referralList.innerHTML =
          referrals
            .map(referral => {

              let statusClass =
                "pending";

              let statusText =
                "AGUARDANDO";

              let description =
                `Aguardando confirmação da matrícula. Elegível em ${fmtDate(
                  referral.eligible_at
                )}`;


              if (
                referral.status ===
                "confirmed"
              ) {

                statusClass =
                  "confirmed";

                statusText =
                  "CONFIRMADA";

                description =
                  "Indicação convertida em matrícula e ticket gerado.";
              }


              if (
                referral.status ===
                "cancelled"
              ) {

                statusClass =
                  "cancelled";

                statusText =
                  "CANCELADA";

                description =
                  "Esta indicação foi cancelada.";
              }


              return `
                <div class="ref-row">

                  <strong>
                    ${escapeHtml(
                      referral.lead_name
                    )}
                  </strong>

                  <span class="status ${statusClass}">
                    ${statusText}
                  </span>

                  <small>
                    ${description}
                  </small>

                </div>
              `;
            })
            .join("");
      }
    }


  } catch (error) {

    console.error(
      "Erro ao carregar área do aluno:",
      error
    );


    if (
      error.status === 401
    ) {

      clearStudentSession();

      location.href =
        "index.html#acessar";

      return;
    }


    toast(
      error.message ||
      "Não foi possível carregar seus dados."
    );
  }
}


/*
==================================================
SEGURANÇA BÁSICA PARA HTML
==================================================
*/

function escapeHtml(value) {

  return String(
    value ?? ""
  )
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );
}


/*
==================================================
INICIALIZAÇÃO
==================================================
*/

if (
  location.pathname.endsWith(
    "/aluno.html"
  )
) {

  initStudent();

} else if (
  !location.pathname.includes(
    "/admin/"
  )
) {

  initPublic();
}
