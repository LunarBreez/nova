//! `nova-gui` : une fenêtre pour lancer un relevé CBOM et en lire le résumé.
//!
//! L'interface ne fait rien que la commande `nova` ne fasse : elle appelle le
//! même collecteur de `nova-core`, sur un fil d'arrière-plan, et écrit les
//! mêmes fichiers.

// Pas de console supplémentaire sous Windows en release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use gpui::{
    App, AppContext, Application, Bounds, Context, FontWeight, Hsla, IntoElement, Render,
    SharedString, TitlebarOptions, Window, WindowBounds, WindowOptions, div, prelude::*, px, rgb,
    size,
};
use nova_core::model::Cbom;
use nova_core::output::Written;
use nova_core::{collect, cyclonedx, files, output};

/// Titre de la fenêtre.
const WINDOW_TITLE: &str = "NOVA";

/// Couleurs du thème sombre.
struct Theme;

impl Theme {
    fn bg() -> Hsla {
        rgb(0x0f1419).into()
    }
    fn panel() -> Hsla {
        rgb(0x1a212b).into()
    }
    fn border() -> Hsla {
        rgb(0x2c3745).into()
    }
    fn text() -> Hsla {
        rgb(0xe6edf3).into()
    }
    fn muted() -> Hsla {
        rgb(0x8b98a8).into()
    }
    fn accent() -> Hsla {
        rgb(0x4c8dff).into()
    }
    fn accent_hover() -> Hsla {
        rgb(0x6ea3ff).into()
    }
    fn warning() -> Hsla {
        rgb(0xe3b341).into()
    }
    fn danger() -> Hsla {
        rgb(0xf47067).into()
    }
    fn success() -> Hsla {
        rgb(0x56d364).into()
    }
}

/// Police d'interface de la plateforme.
fn ui_font() -> &'static str {
    if cfg!(target_os = "windows") {
        "Segoe UI"
    } else {
        "Ubuntu"
    }
}

/// Un relevé terminé.
struct Done {
    cbom: Cbom,
    written: Written,
    /// Chemin de l'export CycloneDX, ou l'erreur rencontrée en l'écrivant.
    export: Option<Result<PathBuf, String>>,
}

/// Où en est le relevé.
enum State {
    Idle,
    Running,
    Done(Box<Done>),
    Failed(String),
}

/// La fenêtre de Nova.
struct NovaWindow {
    state: State,
    with_files: bool,
    output: PathBuf,
}

impl NovaWindow {
    fn new(output: PathBuf) -> Self {
        Self {
            state: State::Idle,
            with_files: true,
            output,
        }
    }

    /// Lance le relevé sur un fil d'arrière-plan.
    fn start(&mut self, cx: &mut Context<Self>) {
        if matches!(self.state, State::Running) {
            return;
        }
        self.state = State::Running;
        cx.notify();
        let options = collect::Options {
            files: self.with_files.then(|| files::Options::for_root("/")),
            ..collect::Options::default()
        };
        let directory = self.output.clone();
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    collect::collect(&options)
                        .and_then(|collected| output::write(&directory, collected))
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                this.state = match result {
                    Ok((cbom, written)) => State::Done(Box::new(Done {
                        cbom,
                        written,
                        export: None,
                    })),
                    Err(error) => State::Failed(error.to_string()),
                };
                cx.notify();
            });
        })
        .detach();
    }

    /// Écrit l'export CycloneDX à côté du relevé.
    fn export(&mut self, cx: &mut Context<Self>) {
        let State::Done(done) = &mut self.state else {
            return;
        };
        let name = done
            .written
            .cbom
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let stem = name.strip_suffix(".cbom.json").unwrap_or(&name);
        let path = done.written.cbom.with_file_name(format!("{stem}.cdx.json"));
        done.export = Some(
            cyclonedx::export_json(&done.cbom)
                .map_err(|error| error.to_string())
                .and_then(|text| std::fs::write(&path, text).map_err(|error| error.to_string()))
                .map(|()| path),
        );
        cx.notify();
    }

    /// Un bouton.
    fn button(
        id: &'static str,
        label: impl Into<SharedString>,
        enabled: bool,
        cx: &mut Context<Self>,
        on_click: impl Fn(&mut Self, &mut Context<Self>) + 'static,
    ) -> impl IntoElement {
        div()
            .id(id)
            .px(px(16.))
            .h(px(36.))
            .flex()
            .items_center()
            .rounded(px(6.))
            .font_weight(FontWeight::MEDIUM)
            .text_color(Theme::bg())
            .bg(if enabled {
                Theme::accent()
            } else {
                Theme::border()
            })
            .when(enabled, |button| {
                button
                    .cursor_pointer()
                    .hover(|style| style.bg(Theme::accent_hover()))
                    .on_click(cx.listener(move |this, _, _, cx| on_click(this, cx)))
            })
            .child(label.into())
    }

    /// Une ligne « libellé : valeur » du résumé.
    fn row(label: &'static str, value: impl Into<SharedString>) -> impl IntoElement {
        div()
            .flex()
            .gap(px(12.))
            .child(
                div()
                    .w(px(170.))
                    .flex_none()
                    .text_color(Theme::muted())
                    .child(label),
            )
            .child(div().flex_1().min_w_0().child(value.into()))
    }

    /// Un encadré titré.
    fn panel(title: &'static str) -> gpui::Div {
        div()
            .flex()
            .flex_col()
            .gap(px(6.))
            .p(px(16.))
            .rounded(px(8.))
            .bg(Theme::panel())
            .border_1()
            .border_color(Theme::border())
            .child(div().font_weight(FontWeight::BOLD).pb(px(4.)).child(title))
    }

    /// Le résumé d'un relevé terminé.
    fn render_done(done: &Done, cx: &mut Context<Self>) -> gpui::Div {
        let cbom = &done.cbom;
        let machine = &cbom.hardware.machine;
        let unknown = || "non renseigné".to_owned();
        let machine_label = match (&machine.vendor, &machine.model) {
            (Some(vendor), Some(model)) => format!("{vendor} {model}"),
            (None, Some(model)) => model.clone(),
            (Some(vendor), None) => vendor.clone(),
            (None, None) => unknown(),
        };
        let firmware_label = cbom
            .firmware
            .components
            .first()
            .map(|firmware| {
                format!(
                    "{} {}",
                    firmware.vendor.as_deref().unwrap_or_default(),
                    firmware.version.as_deref().unwrap_or_default()
                )
                .trim()
                .to_owned()
            })
            .filter(|label| !label.is_empty())
            .unwrap_or_else(unknown);
        let os = &cbom.operating_system;
        let addresses: usize = cbom
            .network
            .interfaces
            .iter()
            .map(|interface| interface.addresses.len())
            .sum();

        let mut summary = Self::panel("Relevé")
            .child(Self::row("Machine", cbom.asset.hostname.clone()))
            .child(Self::row("Matériel", machine_label))
            .child(Self::row("Firmware", firmware_label))
            .child(Self::row(
                "Système",
                os.pretty_name
                    .clone()
                    .or_else(|| os.name.clone())
                    .unwrap_or_else(unknown),
            ))
            .child(Self::row("Logiciels", cbom.software.len().to_string()))
            .child(Self::row(
                "Interfaces réseau",
                format!("{} ({addresses} adresses)", cbom.network.interfaces.len()),
            ))
            .child(Self::row(
                "Ports à l'écoute",
                cbom.network.listening_sockets.len().to_string(),
            ))
            .child(Self::row("Services", cbom.services.len().to_string()))
            .child(Self::row("Comptes", cbom.accounts.len().to_string()));
        if let Some(inventory) = &cbom.files {
            summary = summary.child(Self::row(
                "Fichiers",
                format!(
                    "{} empreintes, {} fichier(s) illisible(s)",
                    inventory.entries - inventory.unreadable,
                    inventory.unreadable
                ),
            ));
        }

        let mut written = Self::panel("Fichiers écrits")
            .child(Self::row("Relevé", done.written.cbom.display().to_string()));
        if let Some(path) = &done.written.files {
            written = written.child(Self::row("Empreintes", path.display().to_string()));
        }
        match &done.export {
            Some(Ok(path)) => {
                written = written.child(Self::row("CycloneDX", path.display().to_string()));
            }
            Some(Err(error)) => {
                written = written.child(
                    div()
                        .text_color(Theme::danger())
                        .child(format!("Export CycloneDX impossible : {error}")),
                );
            }
            None => {}
        }
        written = written.child(div().pt(px(8.)).flex().child(Self::button(
            "exporter",
            "Exporter en CycloneDX",
            done.export.as_ref().is_none_or(|export| export.is_err()),
            cx,
            Self::export,
        )));

        let warnings = &cbom.collection.warnings;
        let mut content = div()
            .flex()
            .flex_col()
            .gap(px(16.))
            .child(summary)
            .child(written);
        if !warnings.is_empty() {
            let mut panel = Self::panel("Avertissements");
            for warning in warnings {
                panel = panel.child(
                    div()
                        .flex()
                        .gap(px(12.))
                        .child(
                            div()
                                .w(px(170.))
                                .flex_none()
                                .text_color(Theme::warning())
                                .child(warning.section.clone()),
                        )
                        .child(div().flex_1().min_w_0().child(warning.message.clone())),
                );
            }
            content = content.child(panel);
        }
        content
    }
}

impl Render for NovaWindow {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let running = matches!(self.state, State::Running);
        let with_files = self.with_files;

        let checkbox = div()
            .id("empreintes")
            .flex()
            .items_center()
            .gap(px(10.))
            .when(!running, |row| {
                row.cursor_pointer().on_click(cx.listener(|this, _, _, cx| {
                    this.with_files = !this.with_files;
                    cx.notify();
                }))
            })
            .child(
                div()
                    .size(px(18.))
                    .rounded(px(4.))
                    .border_1()
                    .border_color(if with_files {
                        Theme::accent()
                    } else {
                        Theme::border()
                    })
                    .bg(if with_files {
                        Theme::accent()
                    } else {
                        Theme::bg()
                    }),
            )
            .child(
                "Relever les empreintes SHA-256 de tous les fichiers (long sur un disque plein)",
            );

        let options = Self::panel("Options")
            .child(checkbox)
            .child(Self::row(
                "Dossier de sortie",
                self.output.display().to_string(),
            ))
            .child(div().pt(px(8.)).flex().child(Self::button(
                "lancer",
                if running {
                    "Relevé en cours…"
                } else {
                    "Lancer le relevé"
                },
                !running,
                cx,
                Self::start,
            )));

        let status = match &self.state {
            State::Idle => div().text_color(Theme::muted()).child(
                "Le relevé lit la machine sans rien modifier et n'émet rien sur le réseau. \
                 Lancé sans droits d'administration, il signale ce qu'il n'a pas pu lire.",
            ),
            State::Running => div().text_color(Theme::muted()).child(if with_files {
                "Relevé en cours : la lecture de tous les fichiers peut prendre plusieurs minutes."
            } else {
                "Relevé en cours…"
            }),
            State::Failed(error) => div()
                .text_color(Theme::danger())
                .child(format!("Le relevé a échoué : {error}")),
            State::Done(done) => div()
                .flex()
                .flex_col()
                .gap(px(16.))
                .child(div().text_color(Theme::success()).child("Relevé terminé."))
                .child(Self::render_done(done, cx)),
        };

        div()
            .id("nova")
            .size_full()
            .overflow_y_scroll()
            .bg(Theme::bg())
            .text_color(Theme::text())
            .text_size(px(14.))
            .font_family(ui_font())
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(16.))
                    .p(px(24.))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap(px(2.))
                            .child(
                                div()
                                    .text_size(px(22.))
                                    .font_weight(FontWeight::BOLD)
                                    .child("NOVA"),
                            )
                            .child(
                                div().text_color(Theme::muted()).child(
                                    "Relevé CBOM (Cyber Bill of Materials) de cette machine",
                                ),
                            ),
                    )
                    .child(options)
                    .child(status),
            )
    }
}

/// Ce que la ligne de commande demande à l'interface.
struct Invocation {
    /// Dossier où écrire le relevé.
    output: PathBuf,
    /// Relever les empreintes de fichiers ?
    with_files: bool,
    /// Lancer le relevé dès l'ouverture de la fenêtre ?
    start: bool,
}

/// Lit la ligne de commande : `nova-gui [--no-files] [--start] [DOSSIER]`.
fn invocation() -> Result<Invocation, String> {
    let mut invocation = Invocation {
        output: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        with_files: true,
        start: false,
    };
    for argument in std::env::args_os().skip(1) {
        match argument.to_str() {
            Some("--no-files") => invocation.with_files = false,
            Some("--start") => invocation.start = true,
            Some(option) if option.starts_with('-') => {
                return Err(format!(
                    "option inconnue : {option}\nusage : nova-gui [--no-files] [--start] [DOSSIER]"
                ));
            }
            _ => invocation.output = PathBuf::from(argument),
        }
    }
    Ok(invocation)
}

fn main() {
    let invocation = match invocation() {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("nova-gui : {message}");
            std::process::exit(2);
        }
    };

    Application::new().run(move |cx: &mut App| {
        let bounds = Bounds::centered(None, size(px(860.), px(760.)), cx);
        let opened = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some(WINDOW_TITLE.into()),
                    ..Default::default()
                }),
                window_min_size: Some(size(px(560.), px(420.))),
                ..Default::default()
            },
            move |_window, cx| {
                cx.new(|cx| {
                    let mut window = NovaWindow::new(invocation.output);
                    window.with_files = invocation.with_files;
                    if invocation.start {
                        window.start(cx);
                    }
                    window
                })
            },
        );
        if let Err(error) = opened {
            eprintln!("nova-gui : ouverture de la fenêtre impossible : {error:#}");
            cx.quit();
            return;
        }
        cx.activate(true);
    });
}
