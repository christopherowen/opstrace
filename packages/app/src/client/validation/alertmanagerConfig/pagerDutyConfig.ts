/**
 * Copyright 2021 Opstrace, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as yup from "yup";

import { httpConfig } from "./common";

const imageConfig = yup.object({
  href: yup.string(),
  source: yup.string(),
  alt: yup.string()
});

const linkConfig = yup.object({
  href: yup.string(),
  text: yup.string()
});

export const pagerDutyConfig = yup.object({
  send_resolved: yup
    .boolean()
    .default(true)
    .meta({ comment: "Whether or not to notify about resolved alerts." }),
  routing_key: yup.string().required().meta({
    comment:
      "The following two options are mutually exclusive. The PagerDuty integration key (when using PagerDuty integration type `Events API v2`)."
  }),
  service_key: yup.string().required().meta({
    comment:
      "The PagerDuty integration key (when using PagerDuty integration type `Prometheus`)."
  }),
  url: yup.string().url().meta({
    comment: "The URL to send API requests to",
    default: "global.pagerduty_url"
  }),
  client: yup
    .string()
    .default('{{ template "pagerduty.default.client" . }}')
    .meta({ comment: "The client identification of the Alertmanager." }),
  client_url: yup
    .string()
    .default('{{ template "pagerduty.default.clientURL" . }}')
    .meta({ comment: "A backlink to the sender of the notification." }),
  description: yup
    .string()
    .default('{{ template "pagerduty.default.description" .}}')
    .meta({ comment: "A description of the incident." }),
  severity: yup
    .string()
    .default("error")
    .meta({ comment: "A description of the incident." }),
  details: yup
    .object()
    .default({
      firing: '{{ template "pagerduty.default.instances" .Alerts.Firing }}',
      resolved: '{{ template "pagerduty.default.instances" .Alerts.Resolved }}',
      num_firing: "{{ .Alerts.Firing | len }}",
      num_resolved: "{{ .Alerts.Resolved | len }}"
    })
    .meta({
      comment:
        "A set of arbitrary key/value pairs that provide further detail about the incident.",
      example: "<string>: <tmpl_string>"
    }),
  images: yup
    .array()
    .of(imageConfig)
    .meta({ comment: "Images to attach to the incident." }),
  links: yup
    .array()
    .of(linkConfig)
    .meta({ comment: "Links to attach to the incident." }),
  http_config: yup.array().of(httpConfig).meta({
    comment: "The HTTP client's configuration.",
    default: "global.http_config"
  })
});
