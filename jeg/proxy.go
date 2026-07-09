package jeg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/uc-cdis/workspace-proxy/proxy"
	"github.com/uc-cdis/workspace-proxy/workspace"
)

func (jeg *JEG) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	// Auth: REMOTE_USER must be present (set by revproxy auth_request).
	// All requests arrive from the browser via remoteKernelsBaseUrl → revproxy.
	remoteUserRaw := strings.TrimSpace(r.Header.Get("REMOTE_USER"))
	identityRaw := strings.TrimSpace(r.Header.Get("X-Gen3-User-ID"))
	if identityRaw == "" {
		identityRaw = remoteUserRaw
	}
	remoteUser := workspace.NormalizeRemoteUser(identityRaw)
	if remoteUser == "" {
		remoteUser = workspace.NormalizeRemoteUser(remoteUserRaw)
	}
	if remoteUser == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		// logAccess("", jegGatewayURL, r.Method, r.URL.Path, http.StatusForbidden, time.Since(start))
		return
	}
	userHash := workspace.HashUser(remoteUser)

	// Strip the /jeg-proxy prefix to get the kernel-API-relative path.
	jegPath := strings.TrimPrefix(r.URL.Path, "/jeg-proxy")
	if jegPath == "" {
		jegPath = "/"
	}

	jegBase, _ := url.Parse(jeg.gatewayURL)

	// Common upstream headers forwarded to JEG.
	forwardJEGHeaders := func(req *http.Request) {
		log.Printf("REMOTE_USER %+v", remoteUser)
		// log.Printf("remote_user %+v", remoteUser)

		req.Header.Set("REMOTE_USER", remoteUser)
		// req.Header.Set("remote_user", remoteUser)
		req.Header.Set("X-Remote-User", remoteUser)
		req.Header.Set("KERNEL_USERNAME", remoteUser)
		req.Header.Del("Connection")
		req.Header.Del("Upgrade")
	}

	method := r.Method

	// Resolve the user's micro-container upstream (soft-fail: empty string if not running).
	// Used to fetch local kernelspecs, route local kernel launches, and proxy contents/sessions.
	microUpstream, _ := workspace.LookupUpstreamWithFallback(ctx, jeg.K8s, remoteUser, identityRaw, remoteUserRaw)

	// ---- Route dispatch ----

	// /api/sessions — simplified now that the browser talks directly to ghost gateway
	// (no more GatewayClient middleman creating shadow sessions).
	// Container handles local kernel sessions; JEG has no session API, so we
	// synthesize session entries from the session-override map for JEG kernels.
	//   - GET  (list):  merge container sessions + synthesized JEG sessions
	//   - GET  (by id): try container, fall back to override map
	//   - POST:         route by kernel name (local -> container, JEG -> synthesize)
	//   - PATCH:        route by kernel in body (local -> container, JEG -> synthesize)
	//   - DELETE:       try container, clear override if present
	if strings.HasPrefix(jegPath, "/api/sessions") {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		proxySessionToContainerBuffered := func() (int, http.Header, []byte, error) {
			log.Printf("&1 microUpstream=%q", microUpstream)
			if microUpstream == "" {
				return http.StatusBadGateway, nil, nil, fmt.Errorf("workspace not running")
			}
			upstream := strings.TrimRight(microUpstream, "/") + proxy.UpstreamPrefix + jegPath
			log.Printf("&2 upstream=%q", upstream)
			log.Printf("&3 method=%q", method)
			log.Printf("&4 jegPath=%q", jegPath)
			log.Printf("&5 proxy.UpstreamPrefix=%q", proxy.UpstreamPrefix)
			log.Printf("&6 body_len=%d", len(body))
			req, _ := http.NewRequest(method, upstream, bytes.NewReader(body))
			log.Printf("&7 req.URL=%q", req.URL.String())
			for key := range r.Header {
				log.Printf("&8 header_key=%q", key)

				switch strings.ToLower(key) {
				case "connection", "upgrade", "te", "trailers", "transfer-encoding":
					log.Printf("&9 skipped_header=%q", key)
					continue
				}
				req.Header[key] = r.Header[key]
				log.Printf("&10 copied_header=%q value=%q", key, req.Header[key])
			}
			req.Header.Set("REMOTE_USER", remoteUser)
			log.Printf("&11 remoteUser=%q", remoteUser)
			if r.URL.RawQuery != "" {
				req.URL.RawQuery = r.URL.RawQuery
				log.Printf("&12 rawQuery=%q", r.URL.RawQuery)
			}

			dump, err := httputil.DumpRequestOut(req, true)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("&77 %s\n", dump)

			resp, err := http.DefaultClient.Do(req)
			log.Printf("&13 err=%v", err)
			if err != nil {
				return http.StatusBadGateway, nil, nil, err
			}
			defer resp.Body.Close()
			log.Printf("&14 statusCode=%d", resp.StatusCode)
			log.Printf("&15 responseHeaders=%v", resp.Header)
			respBody, _ := io.ReadAll(resp.Body)
			log.Printf("&16 respBodyLen=%d", len(respBody))
			return resp.StatusCode, resp.Header, respBody, nil
		}

		writeResponse := func(status int, header http.Header, respBody []byte) {
			for key, vals := range header {
				switch strings.ToLower(key) {
				case "connection", "transfer-encoding", "content-length":
					continue
				}
				for _, v := range vals {
					w.Header().Add(key, v)
				}
			}
			w.WriteHeader(status)
			_, _ = w.Write(respBody)
		}

		// GET /api/sessions — merge container sessions + synthesized JEG sessions.
		if method == http.MethodGet {
			// Single session by ID: try container, then override map.
			if strings.HasPrefix(jegPath, "/api/sessions/") {
				sessionID := strings.TrimPrefix(jegPath, "/api/sessions/")
				sessionID = strings.SplitN(sessionID, "/", 2)[0]
				sessionID = strings.SplitN(sessionID, "?", 2)[0]

				if microUpstream != "" {
					cStatus, cHdr, cBody, cErr := proxySessionToContainerBuffered()
					if cErr == nil && cStatus == http.StatusOK {
						writeResponse(cStatus, cHdr, cBody)
						jeg.logger.InfoContext(ctx, "access5",
							slog.String("user", userHash),
							slog.String("microsupstream", microUpstream),
							slog.String("method", method),
							slog.String("path", r.URL.Path),
							slog.Int("status", cStatus),
							slog.Duration("time", time.Since(start)))
						return
					}
				}
				// Container didn't have it — check override map (JEG synthetic session).
				if override, ok := jeg.getSessionKernelOverride(remoteUser, sessionID); ok {
					out := buildSessionCompatResponse(sessionID, override, nil)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(out)
					jeg.logger.InfoContext(r.Context(), "access4",
						slog.String("user_hash", userHash),
						slog.String("action", "override"),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", http.StatusOK),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
				http.Error(w, "session not found", http.StatusNotFound)
				jeg.logger.InfoContext(r.Context(), "access6",
					slog.String("user_hash", userHash),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusNotFound),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}

			// Session list: merge container sessions + JEG kernel-backed overrides.
			var merged []json.RawMessage
			containerIDs := map[string]struct{}{}

			if microUpstream != "" {
				cStatus, _, cBody, cErr := proxySessionToContainerBuffered()
				if cErr == nil && cStatus == http.StatusOK {
					var sessions []json.RawMessage
					if json.Unmarshal(cBody, &sessions) == nil {
						for _, s := range sessions {
							var sess struct {
								ID string `json:"id"`
							}
							if json.Unmarshal(s, &sess) == nil && strings.TrimSpace(sess.ID) != "" {
								containerIDs[strings.TrimSpace(sess.ID)] = struct{}{}
							}
							merged = append(merged, s)
						}
					}
				}
			}

			// Fetch live JEG kernel data once for enriching synthesized sessions.
			jegKernels := jeg.listJEGKernels(remoteUser)
			jegKernelMap := map[string]*jegKernelInfo{}
			for i := range jegKernels {
				jegKernelMap[strings.TrimSpace(jegKernels[i].ID)] = &jegKernels[i]
			}

			// Synthesize session entries for active JEG kernels from override map.
			prefix := strings.TrimSpace(remoteUser) + "|"
			jeg.sessionKernelOverrides.Range(func(k, v interface{}) bool {
				key, ok := k.(string)
				if !ok || !strings.HasPrefix(key, prefix) {
					return true
				}
				override, ok := v.(sessionKernelOverride)
				if !ok || strings.TrimSpace(override.KernelID) == "" {
					return true
				}
				sid := strings.TrimPrefix(key, prefix)
				if _, dup := containerIDs[sid]; dup {
					return true // skip if container already has a session with this ID
				}
				// Only include if JEG still has the kernel running.
				live, ok := jegKernelMap[strings.TrimSpace(override.KernelID)]
				if !ok {
					jeg.clearSessionKernelOverride(remoteUser, sid)
					return true
				}
				out := buildSessionCompatResponse(sid, override, live)
				merged = append(merged, json.RawMessage(out))
				return true
			})

			if merged == nil {
				merged = []json.RawMessage{}
			}
			result, _ := json.Marshal(merged)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(result)
			jeg.logger.InfoContext(r.Context(), "access7",
				slog.String("user_hash", userHash),
				slog.String("upstream", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusOK),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// POST /api/sessions — route by kernel name.
		if method == http.MethodPost {
			_, postKernelName := extractSessionKernelFromBody(body)
			postKernelName = strings.TrimSpace(postKernelName)

			var postReq struct {
				ID     string `json:"id"`
				Path   string `json:"path"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Kernel struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"kernel"`
			}
			_ = json.Unmarshal(body, &postReq)

			// Determine if this is a local or JEG spec.
			localSpec := false
			if microUpstream != "" && postKernelName != "" {
				localSpec = isLocalContainerSpec(microUpstream, postKernelName, remoteUser)
			}

			log.Printf("&1 localSpec=%+v", localSpec)
			log.Printf("&2 microUpstream=%+v", microUpstream)
			log.Printf("&3 postKernelName=%+v", postKernelName)

			// Local kernel — forward to container.
			if localSpec {
				if microUpstream != "" {
					status, hdr, respBody, err := proxySessionToContainerBuffered()
					if err == nil && status < 400 {
						writeResponse(status, hdr, respBody)
						jeg.logger.InfoContext(r.Context(), "access8",
							slog.String("user_hash", userHash),
							slog.String("upstream", microUpstream),
							slog.String("method", method),
							slog.String("path", r.URL.Path),
							slog.Int("status", status),
							slog.Duration("duration", time.Since(start)),
						)
						return
					}
				}
			}

			// JEG kernel — JEG has no session API, so we synthesize a session.
			// The kernel must already be running (launched via billing panel).
			jegKernelID := strings.TrimSpace(postReq.Kernel.ID)
			if jegKernelID == "" && postKernelName != "" {
				jegKernelID = jeg.findJEGKernelIDByName(remoteUser, postKernelName)
			}

			if jegKernelID != "" && (jeg.isKnownJEGKernelID(jegKernelID) || jeg.jegHasKernel(jegKernelID, remoteUser)) {
				jeg.rememberJEGKernelID(jegKernelID)
				kernelName := strings.TrimSpace(postReq.Kernel.Name)
				if kernelName == "" {
					kernelName = postKernelName
				}
				if kernelName == "" {
					kernelName = jeg.findJEGKernelNameByID(remoteUser, jegKernelID)
				}
				sessType := strings.TrimSpace(postReq.Type)
				if sessType == "" {
					sessType = "notebook"
				}
				newSessionID := strings.TrimSpace(postReq.ID)
				if newSessionID == "" {
					h := sha256.Sum256(fmt.Appendf(nil, "%s-%d", jegKernelID, time.Now().UnixNano()))
					newSessionID = fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
				}
				jeg.setSessionKernelOverride(remoteUser, newSessionID, jegKernelID, kernelName, strings.TrimSpace(postReq.Path), strings.TrimSpace(postReq.Name), sessType)
				out := buildSessionCompatResponse(newSessionID, sessionKernelOverride{
					KernelID: jegKernelID, KernelName: kernelName,
					Path: strings.TrimSpace(postReq.Path), Name: strings.TrimSpace(postReq.Name), Type: sessType,
				}, nil)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(out)
				log.Printf(`{"msg":"jeg session post synthesized","user_hash":%q,"session_id":%q,"kernel_id":%q}`, userHash, newSessionID, jegKernelID)
				jeg.logger.InfoContext(r.Context(), "access9",
					slog.String("user_hash", userHash),
					slog.String("upstream", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusCreated),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}

			// Unknown spec — try container as default.
			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					writeResponse(status, hdr, respBody)
					jeg.logger.InfoContext(r.Context(), "access10",
						slog.String("user_hash", userHash),
						slog.String("upstream", microUpstream),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", status),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
			}

			http.Error(w, "session creation failed", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access11",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// PATCH /api/sessions/{id} — kernel switch.
		if method == http.MethodPatch && strings.HasPrefix(jegPath, "/api/sessions/") {
			sessionID := strings.TrimPrefix(jegPath, "/api/sessions/")
			sessionID = strings.SplitN(sessionID, "/", 2)[0]

			var patchReq struct {
				Path   string `json:"path"`
				Name   string `json:"name"`
				Type   string `json:"type"`
				Kernel struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"kernel"`
			}
			_ = json.Unmarshal(body, &patchReq)

			patchKernelID := strings.TrimSpace(patchReq.Kernel.ID)
			patchKernelName := strings.TrimSpace(patchReq.Kernel.Name)

			// If switching to a JEG kernel, synthesize the response.
			if patchKernelID == "" && patchKernelName != "" {
				patchKernelID = jeg.findJEGKernelIDByName(remoteUser, patchKernelName)
			}
			if patchKernelID != "" && (jeg.isKnownJEGKernelID(patchKernelID) || jeg.jegHasKernel(patchKernelID, remoteUser)) {
				jeg.rememberJEGKernelID(patchKernelID)
				if patchKernelName == "" {
					patchKernelName = jeg.findJEGKernelNameByID(remoteUser, patchKernelID)
				}
				sessPath := strings.TrimSpace(patchReq.Path)
				sessName := strings.TrimSpace(patchReq.Name)
				sessType := strings.TrimSpace(patchReq.Type)
				if sessType == "" {
					sessType = "notebook"
				}
				jeg.setSessionKernelOverride(remoteUser, sessionID, patchKernelID, patchKernelName, sessPath, sessName, sessType)
				out := buildSessionCompatResponse(sessionID, sessionKernelOverride{
					KernelID: patchKernelID, KernelName: patchKernelName,
					Path: sessPath, Name: sessName, Type: sessType,
				}, nil)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(out)
				log.Printf(`{"msg":"jeg session patch synthesized","user_hash":%q,"session_id":%q,"kernel_id":%q}`, userHash, sessionID, patchKernelID)
				jeg.logger.InfoContext(r.Context(), "access12",
					slog.String("user_hash", userHash),
					slog.String("upstream", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusOK),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}

			// If the session is a JEG override with no kernel change, update metadata.
			if patchKernelID == "" && patchKernelName == "" {
				if override, ok := jeg.getSessionKernelOverride(remoteUser, sessionID); ok {
					if strings.TrimSpace(patchReq.Path) != "" {
						override.Path = strings.TrimSpace(patchReq.Path)
					}
					if strings.TrimSpace(patchReq.Name) != "" {
						override.Name = strings.TrimSpace(patchReq.Name)
					}
					if strings.TrimSpace(patchReq.Type) != "" {
						override.Type = strings.TrimSpace(patchReq.Type)
					}
					jeg.setSessionKernelOverride(remoteUser, sessionID, override.KernelID, override.KernelName, override.Path, override.Name, override.Type)
					out := buildSessionCompatResponse(sessionID, override, nil)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(out)
					jeg.logger.InfoContext(r.Context(), "access13",
						slog.String("user_hash", userHash),
						slog.String("upstream", "override"),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", http.StatusOK),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
			}

			// Local kernel switch or unknown — forward to container.
			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					// Switching away from JEG — clear override if present.
					jeg.clearSessionKernelOverride(remoteUser, sessionID)
					writeResponse(status, hdr, respBody)
					jeg.logger.InfoContext(r.Context(), "access14",
						slog.String("user_hash", userHash),
						slog.String("upstream", microUpstream),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", status),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
				// Container 404 on synthetic session — create new local session.
				if status == http.StatusNotFound && patchKernelName != "" &&
					isLocalContainerSpec(microUpstream, patchKernelName, remoteUser) {
					jeg.clearSessionKernelOverride(remoteUser, sessionID)
					sessType := strings.TrimSpace(patchReq.Type)
					if sessType == "" {
						sessType = "notebook"
					}
					postPayload, _ := json.Marshal(map[string]interface{}{
						"path":   patchReq.Path,
						"name":   patchReq.Name,
						"type":   sessType,
						"kernel": map[string]string{"name": patchKernelName},
					})
					up := strings.TrimRight(microUpstream, "/") + proxy.UpstreamPrefix + "/api/sessions"
					pReq, _ := http.NewRequest(http.MethodPost, up, bytes.NewReader(postPayload))
					pReq.Header.Set("Content-Type", "application/json")
					pReq.Header.Set("REMOTE_USER", remoteUser)
					pResp, pErr := http.DefaultClient.Do(pReq)
					if pErr == nil {
						defer pResp.Body.Close()
						pBody, _ := io.ReadAll(pResp.Body)
						pStatus := pResp.StatusCode
						if pStatus == http.StatusCreated {
							pStatus = http.StatusOK
						}
						if pStatus < 400 {
							w.Header().Set("Content-Type", "application/json")
							w.WriteHeader(pStatus)
							_, _ = w.Write(pBody)
							log.Printf(`{"msg":"session patch created local session","user_hash":%q,"kernel":%q}`, userHash, patchKernelName)
							jeg.logger.InfoContext(r.Context(), "access15",
								slog.String("user_hash", userHash),
								slog.String("upstream", microUpstream),
								slog.String("method", method),
								slog.String("path", r.URL.Path),
								slog.Int("status", pStatus),
								slog.Duration("duration", time.Since(start)),
							)
							return
						}
					}
				}
			}

			http.Error(w, "session patch failed", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access16",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// DELETE /api/sessions/{id}
		if method == http.MethodDelete && strings.HasPrefix(jegPath, "/api/sessions/") {
			sessionID := strings.TrimPrefix(jegPath, "/api/sessions/")
			sessionID = strings.SplitN(sessionID, "/", 2)[0]
			jeg.clearSessionKernelOverride(remoteUser, sessionID)

			if microUpstream != "" {
				status, hdr, respBody, err := proxySessionToContainerBuffered()
				if err == nil && status < 400 {
					writeResponse(status, hdr, respBody)
					jeg.logger.InfoContext(r.Context(), "access17",
						slog.String("user_hash", userHash),
						slog.String("upstream", microUpstream),
						slog.String("method", method),
						slog.String("path", r.URL.Path),
						slog.Int("status", status),
						slog.Duration("duration", time.Since(start)),
					)
					return
				}
			}
			// Not in container — 204 regardless (override already cleared).
			w.WriteHeader(http.StatusNoContent)
			jeg.logger.InfoContext(r.Context(), "access18",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusNoContent),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// Other session methods — proxy to container.
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access19",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		status := proxy.ProxyToContainer(w, r, jegPath, microUpstream, remoteUser)
		jeg.logger.InfoContext(r.Context(), "access20",
			slog.String("user_hash", userHash),
			slog.String("upstream", microUpstream),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// /api/contents — always routed to the micro-container (file system is local).
	if strings.HasPrefix(jegPath, "/api/contents") {
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			jeg.logger.InfoContext(r.Context(), "access21",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		status := proxy.ProxyToContainer(w, r, jegPath, microUpstream, remoteUser)
		jeg.logger.InfoContext(r.Context(), "access22",
			slog.String("user_hash", userHash),
			slog.String("upstream", microUpstream),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// WS /api/kernels/{id}/channels — stateless routing with JEG precedence:
	// if JEG owns the kernel ID, always tunnel to JEG; otherwise try container.
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if sid := strings.TrimSpace(r.URL.Query().Get("session_id")); sid != "" {
			if override, ok := jeg.getSessionKernelOverride(remoteUser, sid); ok {
				overrideKernelID := strings.TrimSpace(override.KernelID)
				if overrideKernelID != "" && overrideKernelID != kernelID {
					log.Printf(`{"msg":"jeg channels session override reroute","user_hash":%q,"session_id":%q,"from_kernel_id":%q,"to_kernel_id":%q}`, userHash, sid, kernelID, overrideKernelID)
					kernelID = overrideKernelID
					jeg.rememberJEGKernelID(kernelID)
					jegPath = "/api/kernels/" + kernelID + "/channels"
				}
			}
		}
		jegKnown := jeg.isKnownJEGKernelID(kernelID)
		jegOwns := false
		if kernelID != "" {
			jegOwns = jeg.jegHasKernel(kernelID, remoteUser)
			if jegKnown && !jegOwns {
				jeg.forgetJEGKernelID(kernelID)
				jegKnown = false
			}
		}
		if jegKnown || jegOwns {
			log.Printf(`{"msg":"jeg channels route decision","user_hash":%q,"kernel_id":%q,"route":"jeg","known_jeg_kernel":%t,"jeg_has_kernel":%t}`, userHash, kernelID, jegKnown, jegOwns)
			// JEG kernel — tunnel WS to JEG.
			target := *jegBase
			target.Path = jegPath
			target.RawQuery = r.URL.RawQuery
			// Set user identity headers; do NOT call forwardJEGHeaders here because
			// it deletes Connection and Upgrade from r.Header, which our proxyWebSocket
			// needs to forward in the WS handshake (Sec-WebSocket-Key etc. are in
			// r.Header; Connection/Upgrade are written explicitly by proxyWebSocket).
			r.Header.Set("REMOTE_USER", remoteUser)
			r.Header.Set("remote_user", remoteUser)
			status := proxy.ProxyWebSocket(w, r, &target)
			jeg.logger.InfoContext(r.Context(), "access23",
				slog.String("user_hash", userHash),
				slog.String("upstream", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
		} else if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			log.Printf(`{"msg":"jeg channels route decision","user_hash":%q,"kernel_id":%q,"route":"container"}`, userHash, kernelID)
			// Container owns this kernel — tunnel WS to the container.
			containerWS, _ := url.Parse(microUpstream)
			containerWS.Path = proxy.UpstreamPrefix + jegPath
			containerWS.RawQuery = r.URL.RawQuery
			r.Header.Set("REMOTE_USER", remoteUser)
			status := proxy.ProxyWebSocket(w, r, containerWS)
			jeg.logger.InfoContext(r.Context(), "access24",
				slog.String("user_hash", userHash),
				slog.String("upstream", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
		} else {
			log.Printf(`{"msg":"jeg channels route decision","user_hash":%q,"kernel_id":%q,"route":"jeg-default"}`, userHash, kernelID)
			// Default to JEG when ownership is ambiguous.
			target := *jegBase
			target.Path = jegPath
			target.RawQuery = r.URL.RawQuery
			// Set user identity headers; do NOT call forwardJEGHeaders here because
			// it deletes Connection and Upgrade from r.Header, which our proxyWebSocket
			// needs to forward in the WS handshake (Sec-WebSocket-Key etc. are in
			// r.Header; Connection/Upgrade are written explicitly by proxyWebSocket).
			r.Header.Set("REMOTE_USER", remoteUser)
			r.Header.Set("remote_user", remoteUser)
			status := proxy.ProxyWebSocket(w, r, &target)
			jeg.logger.InfoContext(r.Context(), "access26",
				slog.String("user_hash", userHash),
				slog.String("upstream", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
		}
		return
	}

	// GET /api/kernelspecs — merge local container specs + JEG filtered specs.
	if method == http.MethodGet && jegPath == "/api/kernelspecs" {
		// Fetch JEG specs (may be empty when no policy — that's fine, local fills it).
		jegReq, _ := http.NewRequest(http.MethodGet, jeg.gatewayURL+"/api/kernelspecs", nil)
		forwardJEGHeaders(jegReq)
		jegResp, jegErr := http.DefaultClient.Do(jegReq)
		var jegFiltered []byte
		if jegErr == nil && jegResp.StatusCode == http.StatusOK {
			rawJEG, _ := io.ReadAll(jegResp.Body)
			jegResp.Body.Close()
			jegFiltered = jeg.filterJEGKernelspecs(rawJEG)

			// Ensure kernelspecs for currently running JEG kernels are
			// included even when the policy filters them out, so JupyterLab
			// can display proper kernel names for active sessions.
			runningKernels := jeg.listJEGKernels(remoteUser)
			log.Printf(`{"msg":"kernelspec merge debug","user_hash":%q,"running_kernel_count":%d,"raw_jeg_len":%d,"filtered_len":%d}`, userHash, len(runningKernels), len(rawJEG), len(jegFiltered))
			if len(runningKernels) > 0 {
				var filteredEnv struct {
					Default     string                     `json:"default"`
					Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
				}
				var rawEnv struct {
					Kernelspecs map[string]json.RawMessage `json:"kernelspecs"`
				}
				if json.Unmarshal(jegFiltered, &filteredEnv) == nil && json.Unmarshal(rawJEG, &rawEnv) == nil {
					runningNames := make(map[string]bool)
					for _, k := range runningKernels {
						if n := strings.TrimSpace(k.Name); n != "" {
							runningNames[n] = true
						}
					}
					changed := false
					for specName, specJSON := range rawEnv.Kernelspecs {
						if runningNames[specName] {
							if _, exists := filteredEnv.Kernelspecs[specName]; !exists {
								if filteredEnv.Kernelspecs == nil {
									filteredEnv.Kernelspecs = make(map[string]json.RawMessage)
								}
								filteredEnv.Kernelspecs[specName] = specJSON
								changed = true
							}
						}
					}
					if changed {
						if out, err := json.Marshal(filteredEnv); err == nil {
							jegFiltered = out
							log.Printf(`{"msg":"kernelspec merge added running specs","user_hash":%q,"spec_count":%d}`, userHash, len(filteredEnv.Kernelspecs))
						}
					}
				}
			}
		} else {
			if jegResp != nil {
				jegResp.Body.Close()
			}
			jegFiltered = []byte(`{"default":"","kernelspecs":{}}`)
		}

		// Fetch local container specs and merge.
		var result []byte
		if microUpstream != "" {
			localRaw, localErr := fetchLocalKernelspecs(microUpstream, remoteUser)
			if localErr == nil {
				result = mergeKernelspecs(localRaw, jegFiltered)
			} else {
				log.Printf(`{"msg":"local kernelspecs fetch failed","error":%q}`, localErr.Error())
				result = jegFiltered
			}
		} else {
			result = jegFiltered
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(result)
		jeg.logger.InfoContext(
			r.Context(),
			"access60",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusOK),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// POST /api/kernels — stateless routing: ask the container if it knows the spec.
	// Local spec → forward to container; JEG spec → 403 billing gate.
	if method == http.MethodPost && jegPath == "/api/kernels" {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		var launchReq struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(body, &launchReq)

		if microUpstream != "" && isLocalContainerSpec(microUpstream, launchReq.Name, remoteUser) {
			// Container owns this spec — forward launch to the container's Jupyter.
			r.Body = io.NopCloser(bytes.NewReader(body))
			status := proxy.ProxyToContainer(w, r, "/api/kernels", microUpstream, remoteUser)
			log.Printf(`{"msg":"local kernel launched","spec":%q,"status":%d}`, launchReq.Name, status)
			jeg.logger.InfoContext(
				r.Context(),
				"access61",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}

		// JEG spec (or unknown spec) — billing gate: not allowed via this route.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"GPU kernel launch requires the Vectis Kernel Panel. Select a kernel type there to launch with billing authorization."}`))
		jeg.logger.InfoContext(
			r.Context(),
			"access62",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusForbidden),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// GET /api/kernels/{id} — stateless with JEG precedence.
	if method == http.MethodGet && strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			jeg.logger.InfoContext(
				r.Context(),
				"access63",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadRequest),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if jeg.jegHasKernel(kernelID, remoteUser) {
			// JEG-owned kernel ID.
			upstreamURL := jeg.gatewayURL + jegPath
			req, _ := http.NewRequest(http.MethodGet, upstreamURL, nil)
			forwardJEGHeaders(req)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				http.Error(w, "kernel not found", http.StatusBadGateway)
				jeg.logger.InfoContext(
					r.Context(),
					"access64",
					slog.String("user_hash", userHash),
					slog.String("gateway_url", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", http.StatusBadGateway),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(resp.StatusCode)
			_, _ = w.Write(body)
			jeg.logger.InfoContext(
				r.Context(),
				"access65",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", resp.StatusCode),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			status := proxy.ProxyToContainer(w, r, jegPath, microUpstream, remoteUser)
			jeg.logger.InfoContext(
				r.Context(),
				"access66",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		// Not in container — try JEG.
		upstreamURL := jeg.gatewayURL + jegPath
		req, _ := http.NewRequest(http.MethodGet, upstreamURL, nil)
		forwardJEGHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, "kernel not found", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access67",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			jeg.forgetJEGKernelID(kernelID)
		}
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		jeg.logger.InfoContext(
			r.Context(),
			"access68",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", resp.StatusCode),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// GET /api/kernels — merge container running kernels + JEG running kernels.
	if method == http.MethodGet && jegPath == "/api/kernels" {
		log.Printf("jegPath %+v", jegPath)

		type kernelEntry = json.RawMessage
		var merged []kernelEntry
		jegIDs := map[string]struct{}{}

		// Fetch from JEG.
		jegReq, _ := http.NewRequest(http.MethodGet, jeg.gatewayURL+"/api/kernels", nil)
		forwardJEGHeaders(jegReq)

		if jegResp, err := http.DefaultClient.Do(jegReq); err == nil {
			defer jegResp.Body.Close()
			var jegKernels []kernelEntry
			if jegBody, err := io.ReadAll(jegResp.Body); err == nil {
				log.Printf("jegBody %+v", string(jegBody))
				_ = json.Unmarshal(jegBody, &jegKernels)
				for _, entry := range jegKernels {
					var k struct {
						ID string `json:"id"`
					}
					if json.Unmarshal(entry, &k) == nil {
						jeg.rememberJEGKernelID(k.ID)
						if strings.TrimSpace(k.ID) != "" {
							jegIDs[strings.TrimSpace(k.ID)] = struct{}{}
						}
					}
				}
				merged = append(merged, jegKernels...)
			}
		}

		// Fetch from container.
		if microUpstream != "" {
			containerURL := strings.TrimRight(microUpstream, "/") + proxy.UpstreamPrefix + "/api/kernels"
			contReq, _ := http.NewRequest(http.MethodGet, containerURL, nil)
			contReq.Header.Set("REMOTE_USER", remoteUser)
			if contResp, err := http.DefaultClient.Do(contReq); err == nil {
				defer contResp.Body.Close()
				var localKernels []kernelEntry
				if contBody, err := io.ReadAll(contResp.Body); err == nil {
					if json.Unmarshal(contBody, &localKernels) == nil {
						for _, entry := range localKernels {
							var k struct {
								ID string `json:"id"`
							}
							if json.Unmarshal(entry, &k) != nil {
								continue
							}
							// Skip local kernels whose IDs duplicate a JEG kernel (GatewayClient proxy-through)
							if _, ok := jegIDs[strings.TrimSpace(k.ID)]; ok {
								continue
							}
							merged = append(merged, entry)
						}
						log.Printf(`{"msg":"jeg kernels list merged local","user_hash":%q,"jeg_kernel_count":%d,"local_kernel_count":%d,"merged_total":%d}`, userHash, len(jegIDs), len(localKernels), len(merged))
					}
				}
			}
		}

		if merged == nil {
			merged = []kernelEntry{}
		}
		out, _ := json.Marshal(merged)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
		jeg.logger.InfoContext(
			r.Context(),
			"access69",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", http.StatusOK),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// DELETE /api/kernels/{id} — stateless with JEG precedence.
	if method == http.MethodDelete && strings.HasPrefix(jegPath, "/api/kernels/") {
		kernelID := strings.TrimPrefix(jegPath, "/api/kernels/")
		kernelID = strings.SplitN(kernelID, "/", 2)[0]
		if !isValidKernelID(kernelID) {
			http.Error(w, "Invalid kernel ID", http.StatusBadRequest)
			jeg.logger.InfoContext(
				r.Context(),
				"access70",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadRequest),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if jeg.jegHasKernel(kernelID, remoteUser) {
			// JEG kernel.
			upstream := jeg.gatewayURL + "/api/kernels/" + kernelID
			req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
			forwardJEGHeaders(req)
			resp, err := http.DefaultClient.Do(req)
			status := http.StatusNoContent
			if err != nil {
				status = http.StatusBadGateway
				http.Error(w, "JEG delete failed", status)
				jeg.logger.InfoContext(
					r.Context(),
					"access71",
					slog.String("user_hash", userHash),
					slog.String("gateway_url", jeg.gatewayURL),
					slog.String("method", method),
					slog.String("path", r.URL.Path),
					slog.Int("status", status),
					slog.Duration("duration", time.Since(start)),
				)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(resp.StatusCode)
			}
			jeg.logger.InfoContext(
				r.Context(),
				"access72",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		if microUpstream != "" && containerHasKernel(microUpstream, kernelID, remoteUser) {
			status := proxy.ProxyToContainer(w, r, "/api/kernels/"+kernelID, microUpstream, remoteUser)
			jeg.logger.InfoContext(
				r.Context(),
				"access73",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", microUpstream),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		// JEG kernel.
		upstream := jeg.gatewayURL + "/api/kernels/" + kernelID
		req, _ := http.NewRequest(http.MethodDelete, upstream, nil)
		forwardJEGHeaders(req)
		resp, err := http.DefaultClient.Do(req)
		status := http.StatusNoContent
		if err != nil {
			status = http.StatusBadGateway
			http.Error(w, "JEG delete failed", status)
			jeg.logger.InfoContext(
				r.Context(),
				"access74",
				slog.String("user_hash", userHash),
				slog.String("gateway_url", jeg.gatewayURL),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", status),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNoContent {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(resp.StatusCode)
		}
		jeg.logger.InfoContext(
			r.Context(),
			"access75",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", jeg.gatewayURL),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// /lw-workspace/proxy/... — resource URLs (kernelspec logos, static assets) whose
	// absolute form was embedded in our GET /api/kernelspecs response. JupyterLite
	// constructs fetch URLs as remoteKernelsBaseUrl + resource_url, where resource_url
	// already contains /lw-workspace/proxy/, producing a double-prefix. Strip the
	// extra prefix and proxy the resource to the container.
	if strings.HasPrefix(jegPath, proxy.UpstreamPrefix+"/") {
		containerPath := strings.TrimPrefix(jegPath, proxy.UpstreamPrefix)
		if microUpstream == "" {
			http.Error(w, "workspace not running", http.StatusBadGateway)
			jeg.logger.InfoContext(
				r.Context(),
				"access76",
				slog.String("user_hash", userHash),
				slog.String("method", method),
				slog.String("path", r.URL.Path),
				slog.Int("status", http.StatusBadGateway),
				slog.Duration("duration", time.Since(start)),
			)
			return
		}
		status := proxy.ProxyToContainer(w, r, containerPath, microUpstream, remoteUser)
		jeg.logger.InfoContext(
			r.Context(),
			"access77",
			slog.String("user_hash", userHash),
			slog.String("gateway_url", microUpstream),
			slog.String("method", method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Duration("duration", time.Since(start)),
		)
		return
	}

	// All other paths: not supported by this gateway.
	http.Error(w, "Not found", http.StatusNotFound)
	jeg.logger.InfoContext(
		r.Context(),
		"access78",
		slog.String("user_hash", userHash),
		slog.String("gateway_url", jeg.gatewayURL),
		slog.String("method", method),
		slog.String("path", r.URL.Path),
		slog.Int("status", http.StatusNotFound),
		slog.Duration("duration", time.Since(start)),
	)
}
