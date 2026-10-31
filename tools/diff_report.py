"""Markdown diff report between two analyze_firmware.py results.

    python -I tools/diff_report.py <device_name> <old_dir> <new_dir> <triage.json> <report.md>
"""
import difflib
import json
import re
import sys
from pathlib import Path

ROOT_LABELS = {"empty": "vazia", "locked": "bloqueada", "hash": "definida", None: "desconhecida"}
STATUS_LABELS = {
    "likely_present": "Provavelmente presente",
    "possibly_affected": "Por confirmar",
    "no_security_impact": "Presente, sem impacto",
    "unused": "Código sem uso",
    "not_applicable": "Não aplicável",
    "fixed": "Corrigido",
}
STATUS_ORDER = list(STATUS_LABELS)
ACTIVE_CATEGORIES = ("builtin", "image_module", "header", "wireless_backport")
OPEN_STATUSES = ("likely_present", "possibly_affected")
REVIEW_SCORE = 8.0
KEY_PACKAGES = [
    "kernel", "busybox", "dropbear", "dnsmasq", "uhttpd", "firewall4", "nftables-json",
    "wpad-basic-mbedtls", "libmbedtls21", "libustream-mbedtls", "ca-bundle", "musl",
    "libc", "opkg", "apk-mbedtls",
]


def version(data):
    return re.search(r"DISTRIB_RELEASE='([^']+)'", data["release"]).group(1)


def is_library(path):
    return ".so" in path.rsplit("/", 1)[1]


def hardening(data):
    elfs = {p: f["elf"] for p, f in data["files"].items() if "elf" in f}
    programs = {p: e for p, e in elfs.items() if e["type"] != "rel" and not is_library(p)}
    libraries = {p: e for p, e in elfs.items() if e["type"] != "rel" and is_library(p)}
    userland = {**programs, **libraries}
    return {
        "programs": len(programs),
        "libraries": len(libraries),
        "kernel_modules": len(elfs) - len(userland),
        "pie": sum(e["type"] == "dyn" for e in programs.values()),
        "non_pie": sorted(p for p, e in programs.items() if e["type"] == "exec"),
        "nx": sum(e["nx"] for e in userland.values()),
        "full_relro": sum(e["relro"] and e["bind_now"] for e in userland.values()),
        "canary": sum(e["canary"] for e in userland.values()),
        "userland": len(userland),
    }


def package_key(name, packages):
    """Library packages embed an ABI suffix, so match on the unversioned stem too."""
    if name in packages:
        return name
    stem = re.sub(r"\d+$", "", name)
    return next((p for p in packages if re.fullmatch(re.escape(stem) + r"\d*", p)), None)


def bullets(values):
    return ", ".join(f"`{v}`" for v in values) if values else "nenhum"


def findings_table(cves):
    rows = ["| CVE | Componente | CVSS | Estado | Base da classificação |", "| --- | --- | --- | --- | --- |"]
    ordered = sorted(cves["findings"], key=lambda f: (STATUS_ORDER.index(f["status"]), -(f["score"] or 0), f["cve"]))
    for finding in ordered:
        score = finding["score"] if finding["score"] is not None else "—"
        rows.append(
            f"| {finding['cve']} | {finding['component']} {finding['version']} | {score} "
            f"| {STATUS_LABELS[finding['status']]} | {finding['reason']} |"
        )
    return rows


def code_list(paths):
    return ", ".join(f"`{p}`" for p in paths) if paths else "nenhuma"


def vulnerability_section(old_cves, new_cves, old_kernel, new_kernel, checks, triage, old_v, new_v):
    out = [
        "## Vulnerabilidades",
        "",
        f"Candidatos por versão no NVD e no OSV, consultados a {min(old_cves['consulted'], new_cves['consulted'])}. A classificação manual, quando existe, usa patches, commits e bytes da imagem.",
        "",
        f"| Estado | {old_v} | {new_v} |",
        "| --- | --- | --- |",
    ]
    for status in STATUS_ORDER:
        counts = [sum(f["status"] == status for f in c["findings"]) for c in (old_cves, new_cves)]
        if any(counts):
            out.append(f"| {STATUS_LABELS[status]} | {counts[0]} | {counts[1]} |")
    out.append(f"| **Total de candidatos** | **{len(old_cves['findings'])}** | **{len(new_cves['findings'])}** |")
    for release, cves in ((old_v, old_cves), (new_v, new_cves)):
        out += ["", f"### OpenWrt {release}", "", *findings_table(cves)]
    return out + kernel_section(old_kernel, new_kernel, checks, triage, old_v, new_v)


def kernel_section(old_k, new_k, checks, triage, old_v, new_v):
    verdicts = {
        old_k["version"]: triage.get(old_v, {}).get("kernel", {}),
        new_k["version"]: triage.get(new_v, {}).get("kernel", {}),
    }

    def funnel(label, field):
        return f"| {label} | {field(old_k)} | {field(new_k)} |"

    def tally(*categories):
        return lambda k: sum(k["tally"].get(c, 0) for c in categories)

    def status(k, finding):
        return verdicts[k["version"]].get(finding["cve"], {}).get("status", "possibly_affected")

    def active(k):
        return [f for f in k["findings"] if f["category"] in ACTIVE_CATEGORIES]

    def still_open(k):
        return [f for f in active(k) if status(k, f) in OPEN_STATUSES]

    def severity(label):
        return lambda k: sum((f["severity"] or "UNSCORED") == label for f in still_open(k))

    out = [
        "",
        "### Kernel",
        "",
        "Cada candidato foi comparado com os ficheiros e funções compilados, listados no DWARF oficial do `kernel-debug`, e com as versões corrigidas publicadas pela Linux CNA.",
        "Um candidato só sai da lista com prova positiva. Os casos sem prova ficam em \"Por rever\". Se a correção mudar uma estrutura, ou se a alteração não for localizada no código, o CVE fica em aberto.",
        "",
        f"| Etapa | {old_k['version']} | {new_k['version']} |",
        "| --- | --- | --- |",
        funnel("Candidatos iniciais (NVD + OSV)", lambda k: k["total"]),
        funnel("Corrigido nesta versão, ou nunca presente", tally("fixed_in_version")),
        funnel("Código não compilado", tally("not_compiled")),
        funnel("Só em módulo opcional, fora da imagem", tally("optional_module")),
        funnel("Ficheiro compilado, mas a função alterada não", tally("function_not_compiled")),
        funnel("Por rever, sem prova suficiente", lambda k: k["review"]),
        funnel("Compilado, antes da revisão manual", lambda k: k["active"]),
        funnel("Retirados na revisão manual", lambda k: len(active(k)) - len(still_open(k))),
        funnel("**Em aberto após a revisão**", lambda k: f"**{len(still_open(k))}**"),
        funnel("Críticos em aberto (CVSS)", severity("CRITICAL")),
        funnel("Altos em aberto (CVSS)", severity("HIGH")),
        funnel("Médios em aberto (CVSS)", severity("MEDIUM")),
        funnel("Em aberto sem nota", severity("UNSCORED")),
        "",
        "\"Em aberto\" significa que o ficheiro está compilado e a correção não foi demonstrada. Não significa que a falha seja explorável neste router.",
        f"A revisão manual cobriu os CVEs em aberto com CVSS igual ou superior a {REVIEW_SCORE}. Os restantes seguem a classificação automática.",
        "A diferença entre versões é um sinal, não uma medida de risco: depende também do que foi registado para cada série.",
        "",
        "**Retirados pelo filtro de funções:**",
        "",
        "| Versão | CVE | CVSS | Código alterado pela correção, ausente nesta compilação |",
        "| --- | --- | --- | --- |",
    ]
    for release, data in ((old_v, old_k), (new_v, new_k)):
        for finding in data["findings"]:
            if finding["category"] == "function_not_compiled":
                out.append(f"| {release} | {finding['cve']} | {finding['score'] or '—'} | `{finding['where']}` |")
    out.append("")
    for release, data in ((old_v, old_k), (new_v, new_k)):
        rows = [f for f in data["findings"] if f["category"] in (*ACTIVE_CATEGORIES, "driver_fork") and (f["score"] or 0) >= REVIEW_SCORE]
        out += [
            f"**Revisão manual em {release}:**",
            "",
            "| CVE | CVSS | Estado | Base da classificação |",
            "| --- | --- | --- | --- |",
        ]
        for finding in rows:
            reason = verdicts[data["version"]].get(finding["cve"], {}).get("reason", "Sem triagem manual.")
            out.append(f"| {finding['cve']} | {finding['score']} | {STATUS_LABELS[status(data, finding)]} | {reason} |")
        out.append("")
    old_c, new_c = checks
    banners = [k["kernel_match"]["banner_at_debug_address"] for k in (old_k, new_k)]
    unresolved = old_c["fixed"]["unresolved"] + new_c["fixed"]["unresolved"]
    by_hand = sorted(set(old_c["fixed"]["by_hand"] + new_c["fixed"]["by_hand"]))
    failed = [path for c in (old_c, new_c) for path, passed in c["filter"]["controls"].items() if not passed]
    controls = sorted({path for c in (old_c, new_c) for path in c["filter"]["controls"]})
    exceptions = sorted(set(old_c["filter"]["contradictions"] + new_c["filter"]["contradictions"]))
    old_f, new_f = old_c["functions"], new_c["functions"]
    out += [
        "**Como isto foi validado:**",
        "",
        f"- **Kernel certo:** {'nas duas versões, o `init_uts_ns` da imagem está no endereço dado pelos símbolos de depuração' if all(banners) else 'o kernel da imagem não foi confirmado nos símbolos de depuração em todas as versões'} ({old_k['version']} e {new_k['version']}). O `linux_banner` tem um desvio de {old_k['kernel_match']['banner_shift_bytes']} e {new_k['kernel_match']['banner_shift_bytes']} bytes.{' Este desvio não está explicado, por isso a prova é mais fraca do que um endereço exato.' if old_k['kernel_match']['banner_shift_bytes'] or new_k['kernel_match']['banner_shift_bytes'] else ''}",
        f"- **Vereditos \"corrigido\" em código compilado:** {old_c['fixed']['total']} na {old_k['version']} e {new_c['fixed']['total']} na {new_k['version']}. A ferramenta confirmou {old_c['fixed']['tool']} e {new_c['fixed']['tool']} no código real. À mão: {code_list(by_hand)}. Por confirmar: {code_list(unresolved)}.",
        f"- **Código \"não compilado\":** das regras diretas das Makefiles, {old_c['filter']['disabled']} de {old_c['filter']['checked']} e {new_c['filter']['disabled']} de {new_c['filter']['checked']} têm a opção desligada no `.config` real. Exceções: {code_list(exceptions)}.",
        f"- **Controlos:** {code_list(controls)}. {'Todos ficaram na categoria esperada.' if not failed else 'Falharam: ' + code_list(sorted(set(failed))) + '.'}",
        f"- **Filtro de funções:** {old_f['proved']} de {old_f['retired']} e {new_f['proved']} de {new_f['retired']} retirados confirmados fora da DWARF: a alteração está num módulo fora da imagem, ou numa função sem símbolo atrás de uma opção desligada no `.config` real.",
        f"- **Funções dos ficheiros compilados:** {old_f['present']} e {new_f['present']} estão na DWARF, {old_f['absent_guarded']} e {new_f['absent_guarded']} estão atrás de opções desligadas, e {old_f['absent_unexplained']} e {new_f['absent_unexplained']} não têm rasto no binário nem opção identificada. Outras {old_f['absent_with_symbol']} e {new_f['absent_with_symbol']} têm um símbolo com o mesmo nome, vindo de outro ficheiro ou de assembly. Um nome presente noutro ficheiro da DWARF conta como compilado.",
        "",
    ]
    return out


def report(device, old, new, old_cves, new_cves, old_kernel, new_kernel, checks, triage):
    old_v, new_v = version(old), version(new)
    old_h, new_h = hardening(old), hardening(new)
    old_p, new_p = old["packages"], new["packages"]
    added = sorted(set(new_p) - set(old_p))
    removed = sorted(set(old_p) - set(new_p))
    changed = sorted(p for p in set(old_p) & set(new_p) if old_p[p] != new_p[p])
    old_programs = {p for p, f in old["files"].items() if "elf" in f and f["elf"]["type"] != "rel" and not is_library(p)}
    new_programs = {p for p, f in new["files"].items() if "elf" in f and f["elf"]["type"] != "rel" and not is_library(p)}

    out = [
        f"# {device}: OpenWrt {old_v} → {new_v}",
        "",
        "Análise estática das imagens `sysupgrade` oficiais. Nenhum código do firmware foi executado.",
        "",
        "## Resumo",
        "",
        "| Medida | " + old_v + " | " + new_v + " |",
        "| --- | --- | --- |",
        f"| Kernel | `{old['kernel_image']}` | `{new['kernel_image']}` |",
        f"| Gestor de pacotes | {old['package_manager']} | {new['package_manager']} |",
        f"| Tamanho da imagem | {old['bytes']:,} bytes | {new['bytes']:,} bytes |",
        f"| Pacotes instalados | {len(old_p)} | {len(new_p)} |",
        f"| Entradas de ficheiros | {len(old['files'])} | {len(new['files'])} |",
        f"| Programas PIE | {old_h['pie']} de {old_h['programs']} | {new_h['pie']} de {new_h['programs']} |",
        f"| Marcados NX | {old_h['nx']} de {old_h['userland']} | {new_h['nx']} de {new_h['userland']} |",
        f"| Full RELRO | {old_h['full_relro']} de {old_h['userland']} | {new_h['full_relro']} de {new_h['userland']} |",
        f"| Com canário de pilha | {old_h['canary']} de {old_h['userland']} | {new_h['canary']} de {new_h['userland']} |",
        f"| Ficheiros setuid/setgid | {sum(1 for f in old['files'].values() if f.get('setuid'))} | {sum(1 for f in new['files'].values() if f.get('setuid'))} |",
        f"| Candidatos a segredos | {len(old['secret_candidates'])} | {len(new['secret_candidates'])} |",
        f"| Palavra-passe de `root` por omissão | {ROOT_LABELS[old['accounts'].get('root')]} | {ROOT_LABELS[new['accounts'].get('root')]} |",
        "",
        "## Componentes principais",
        "",
        "| Pacote | " + old_v + " | " + new_v + " |",
        "| --- | --- | --- |",
    ]
    for name in KEY_PACKAGES:
        old_key, new_key = package_key(name, old_p), package_key(name, new_p)
        if old_key or new_key:
            out.append(f"| {name} | {old_p.get(old_key, '—')} | {new_p.get(new_key, '—')} |")

    out += [
        "",
        "## Pacotes",
        "",
        f"{len(added)} adicionados, {len(removed)} removidos e {len(changed)} com versão alterada.",
        "",
        f"- **Adicionados:** {bullets(added)}",
        f"- **Removidos:** {bullets(removed)}",
        "",
        "## Serviços e programas",
        "",
        f"- **Scripts de serviço adicionados:** {bullets(sorted(set(new['services']) - set(old['services'])))}",
        f"- **Scripts de serviço removidos:** {bullets(sorted(set(old['services']) - set(new['services'])))}",
        f"- **Arranque automático adicionado:** {bullets(sorted(set(new['enabled_services']) - set(old['enabled_services'])))}",
        f"- **Arranque automático removido:** {bullets(sorted(set(old['enabled_services']) - set(new['enabled_services'])))}",
        f"- **Programas adicionados:** {bullets(sorted(new_programs - old_programs))}",
        f"- **Programas removidos:** {bullets(sorted(old_programs - new_programs))}",
        f"- **Programas sem PIE em {new_v}:** {bullets(new_h['non_pie'])}",
        "",
        "## Configurações por omissão",
        "",
    ]
    for path in sorted(set(old["configs"]) | set(new["configs"])):
        diff = list(difflib.unified_diff(
            old["configs"].get(path, "").splitlines(), new["configs"].get(path, "").splitlines(),
            old_v, new_v, lineterm="", n=3,
        ))
        out.append(f"**`{path}`:** " + ("sem alterações." if not diff else ""))
        if diff:
            out += ["", "```diff", *diff, "```"]
        out.append("")

    out += vulnerability_section(old_cves, new_cves, old_kernel, new_kernel, checks, triage, old_v, new_v)
    out += [
        "## Limites desta análise",
        "",
        "- A comparação cobre a configuração incluída na imagem, não o que corre num router já configurado.",
        "- `NX` é a marca no ELF. Não prova que o processador a aplique neste dispositivo.",
        "- A ausência de canário significa que o binário não referencia `__stack_chk_fail`, o que pode acontecer sem haver funções a proteger.",
        "- Um CVE do kernel fica em aberto se uma função alterada pela correção estiver compilada, ou se a alteração não puder ser mapeada para uma função. Isto não prova que a função seja alcançável nem que a funcionalidade esteja ativa.",
        "- O filtro de funções não cobre o Wi-Fi nem alterações a estruturas e macros. Esses CVEs ficam em aberto.",
        "- Um cabeçalho só com macros não deixa rasto na DWARF. Quando está junto de código compilado, o CVE fica em \"Por rever\".",
        "- As versões corrigidas vêm da Linux CNA. A confirmação no código usou o kernel oficial, sem as patches que o OpenWrt lhe aplica.",
        "- O Wi-Fi usa backports. Os seus vereditos seguem a versão dos backports e só foram confirmados no código quando a revisão manual o indica. Drivers com árvore própria, como ath10k-ct e mt76, ficam em \"Por rever\".",
        "- A revisão manual avaliou a configuração incluída na imagem. Um CVE marcado como \"Código sem uso\" volta a contar se a funcionalidade for ativada.",
        "- Módulos opcionais estão fora da contagem, mas passam a contar se forem instalados.",
        "- Os estados das vulnerabilidades vêm de análise estática: nenhuma falha foi testada num dispositivo.",
        "- Os pacotes hostapd/wpad usam snapshots por data e não têm versão upstream comparável, por isso não foram correlacionados.",
        "- Instalar pacotes extra pode tornar relevantes componentes marcados como não aplicáveis ou sem uso.",
        "",
        "## Proveniência",
        "",
        f"- `{old['image']}`: SHA-256 `{old['sha256']}`",
        f"- `{new['image']}`: SHA-256 `{new['sha256']}`",
    ]
    return "\n".join(out) + "\n"


def load(folder, name):
    return json.loads((Path(folder) / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    device, old_dir, new_dir, triage_path, output = sys.argv[1:6]
    folders = (old_dir, new_dir)
    checks = [{name: load(f, f"check-{name}.json") for name in ("filter", "fixed", "functions")} for f in folders]
    triage = json.loads(Path(triage_path).read_text(encoding="utf-8")) if Path(triage_path).exists() else {}
    analyses, cves, kernels = ([load(f, name) for f in folders] for name in ("analysis.json", "cves.json", "kernel-refined.json"))
    Path(output).write_text(report(device, *analyses, *cves, *kernels, checks, triage), encoding="utf-8")
