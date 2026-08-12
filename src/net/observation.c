#include "qanat/observation.h"

#include "qanat/util.h"

#include <string.h>

const char *qn_highest_rung_str(qn_highest_rung rung)
{
    switch (rung) {
    case QN_RUNG_NONE:    return "none";
    case QN_RUNG_TCP:     return "tcp";
    case QN_RUNG_TLS:     return "handshake";
    case QN_RUNG_HTTP:    return "http";
    case QN_RUNG_EDGE:    return "cf-marker-observed";
    case QN_RUNG_FLOWING: return "flowing-after-marker";
    case QN_RUNG_STABLE:  return "stable-after-marker";
    default:              return "invalid";
    }
}

const char *qn_terminal_outcome_str(qn_terminal_outcome outcome)
{
    switch (outcome) {
    case QN_TERM_NONE:             return "pending";
    case QN_TERM_SUCCESS:          return "success";
    case QN_TERM_DEAD:             return "dead";
    case QN_TERM_LOCAL_ERROR:      return "local-error";
    case QN_TERM_INCONCLUSIVE:     return "inconclusive";
    case QN_TERM_PEER_REJECTED:    return "peer-rejected";
    case QN_TERM_UNSUPPORTED:      return "unsupported";
    case QN_TERM_PROTOCOL_INVALID: return "protocol-invalid";
    case QN_TERM_RESET:            return "reset";
    case QN_TERM_TIMEOUT:          return "timeout";
    case QN_TERM_CANCELLED:        return "cancelled";
    case QN_TERM_INTERFERENCE:     return "interference-suspected";
    default:                       return "invalid";
    }
}

const char *qn_classification_str(qn_classification classification)
{
    if (classification.terminal_outcome == QN_TERM_SUCCESS)
        return qn_highest_rung_str(classification.highest_rung_reached);
    return qn_terminal_outcome_str(classification.terminal_outcome);
}

bool qn_classification_has_tls(qn_classification classification)
{
    return classification.terminal_outcome == QN_TERM_SUCCESS &&
           classification.highest_rung_reached >= QN_RUNG_TLS &&
           classification.highest_rung_reached < QN_RUNG_COUNT;
}

bool qn_classification_has_marker(qn_classification classification)
{
    return classification.terminal_outcome == QN_TERM_SUCCESS &&
           classification.highest_rung_reached >= QN_RUNG_EDGE &&
           classification.highest_rung_reached < QN_RUNG_COUNT;
}

qn_classification qn_cf_record_classification(const cf_record *record)
{
    qn_classification classification = { QN_RUNG_NONE, QN_TERM_NONE };

    if (!record)
        return classification;
    classification.highest_rung_reached =
        (qn_highest_rung)record->highest_rung_reached;
    classification.terminal_outcome =
        (qn_terminal_outcome)record->terminal_outcome;
    return classification;
}

void qn_observation_init(qn_observation *observation)
{
    if (observation)
        memset(observation, 0, sizeof *observation);
}

void qn_edge_policy_apply(qn_observation *observation)
{
    if (!observation)
        return;
    observation->edge.weak_header = observation->http.cf_ray ||
                                    observation->http.server_cloudflare;
    observation->edge.trace_colo = observation->http.trace_colo;
    observation->edge.verified = observation->transport.connected &&
                                 observation->tls.handshake_complete &&
                                 observation->http.request_fully_flushed &&
                                 observation->http.final_headers &&
                                 observation->http.status == 200u &&
                                 observation->http.trace_colo;
    if (observation->edge.verified)
        memcpy(observation->edge.colo, observation->http.colo,
               sizeof observation->edge.colo);
}

void qn_observation_apply_http(qn_observation *observation,
                               const qn_http_event *event)
{
    if (!observation || !event || event->response_index != 1u)
        return;

    if (event->flags & QN_HTTP_FACT_INFORMATIONAL)
        observation->http.informational_responses++;
    /* Trailers close a response; they never restate or replace its status. */
    if (event->flags & QN_HTTP_FACT_TRAILERS)
        observation->http.trailers = true;
    /* The first final head is the response's status; nothing later rewrites it. */
    if ((event->flags & QN_HTTP_FACT_HEADERS) && !observation->http.final_headers) {
        observation->http.final_headers = true;
        observation->http.status = event->status;
    }
    if (event->flags & QN_HTTP_FACT_BODY)
        observation->http.body_bytes += event->body_bytes;
    if (event->flags & QN_HTTP_FACT_DONE)
        observation->http.response_complete = true;
    if (event->flags & QN_HTTP_FACT_CF_RAY)
        observation->http.cf_ray = true;
    if (event->flags & QN_HTTP_FACT_SERVER_CLOUDFLARE)
        observation->http.server_cloudflare = true;
    if (event->flags & QN_HTTP_FACT_TRACE_COLO) {
        observation->http.trace_colo = true;
        memcpy(observation->http.colo, event->colo,
               sizeof observation->http.colo);
    }
    qn_edge_policy_apply(observation);
}

void qn_observation_fail(qn_observation *observation,
                         qn_terminal_outcome outcome,
                         qn_failure_origin origin, int sys_errno,
                         int protocol_code, const char *reason)
{
    if (!observation || outcome <= QN_TERM_SUCCESS || outcome >= QN_TERM_COUNT)
        return;
    observation->terminal.outcome = (uint8_t)outcome;
    observation->terminal.origin = (uint8_t)origin;
    observation->terminal.sys_errno = sys_errno;
    observation->terminal.protocol_code = protocol_code;
    if (reason && !observation->terminal.reason[0])
        qn_strlcpy(observation->terminal.reason, reason,
                   sizeof observation->terminal.reason);
}

qn_classification qn_observation_classify(const qn_observation *observation)
{
    qn_classification result = { QN_RUNG_NONE, QN_TERM_NONE };

    if (!observation)
        return result;

    if (observation->transport.connected)
        result.highest_rung_reached = QN_RUNG_TCP;
    if (result.highest_rung_reached == QN_RUNG_TCP &&
        observation->tls.handshake_complete)
        result.highest_rung_reached = QN_RUNG_TLS;
    if (result.highest_rung_reached == QN_RUNG_TLS &&
        observation->http.final_headers)
        result.highest_rung_reached = QN_RUNG_HTTP;
    if (result.highest_rung_reached == QN_RUNG_HTTP &&
        observation->edge.verified)
        result.highest_rung_reached = QN_RUNG_EDGE;
    if (result.highest_rung_reached == QN_RUNG_EDGE &&
        observation->flow.completed)
        result.highest_rung_reached = QN_RUNG_FLOWING;
    if (result.highest_rung_reached >= QN_RUNG_EDGE &&
        observation->stability.survived)
        result.highest_rung_reached = QN_RUNG_STABLE;

    if (observation->terminal.outcome > QN_TERM_NONE &&
        observation->terminal.outcome < QN_TERM_COUNT)
        result.terminal_outcome =
            (qn_terminal_outcome)observation->terminal.outcome;
    else if (observation->completed)
        result.terminal_outcome = observation->transport.connected
                                      ? QN_TERM_SUCCESS
                                      : QN_TERM_DEAD;
    return result;
}
