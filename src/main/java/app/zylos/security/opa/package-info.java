/**
 * OPA client and decision-cache decorator.
 *
 * <p>The starter provides two HTTP client backends ({@link
 * app.zylos.security.opa.RestClientOpaClient} for servlet, {@link
 * app.zylos.security.opa.WebClientOpaClient} for reactive) and a stack-
 * agnostic Caffeine-backed cache decorator ({@link
 * app.zylos.security.opa.CachingOpaClient}). The auto-configuration wires
 * the appropriate backend behind the cache decorator and exposes a single
 * {@link app.zylos.security.opa.OpaClient} bean.
 *
 * <p>OPA's REST API is intentionally narrow: a single endpoint
 * ({@code POST /v1/data/{path}}) with a single envelope shape
 * ({@code {"input": ...}} request, {@code {"result": ...}} response). The
 * starter rolls a thin client rather than depending on the official OPA
 * Java SDK; rationale in {@code docs/adr/0004-opa-integration.md}.
 */
@NullMarked
package app.zylos.security.opa;

import org.jspecify.annotations.NullMarked;
