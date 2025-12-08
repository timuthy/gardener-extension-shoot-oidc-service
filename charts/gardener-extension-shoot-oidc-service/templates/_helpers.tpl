{{-  define "image" -}}
  {{- if hasPrefix "sha256:" .Values.image.tag }}
  {{- printf "%s@%s" .Values.image.repository .Values.image.tag }}
  {{- else }}
  {{- printf "%s:%s" .Values.image.repository .Values.image.tag }}
  {{- end }}
{{- end }}

{{- define "leaderelectionid" -}}
extension-shoot-oidc-service-leader-election
{{- end -}}

{{- define "name" -}}
{{- if .Values.gardener.runtimeCluster.enabled -}}
shoot-oidc-service-runtime
{{- else -}}
shoot-oidc-service
{{- end -}}
{{- end -}}
