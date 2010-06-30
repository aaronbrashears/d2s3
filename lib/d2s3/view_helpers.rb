require 'base64'

module D2S3
  module ViewHelpers
    include D2S3::Signature

    def s3_http_upload_tag(options = {})
      bucket          = D2S3::S3Config.bucket
      access_key_id   = D2S3::S3Config.access_key_id
      key             = options[:key] || ''
      content_type    = options[:content_type] || '' # Defaults to binary/octet-stream if blank
      redirect        = options[:redirect] || '/'
      acl             = options[:acl] || 'public-read'
      expiration_date = (options[:expiration_date] || 10.hours).from_now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')
      max_filesize    = options[:max_filesize] || 1.megabyte
      min_filesize    = options[:min_filesize] || 1.byte
      submit_button   = options[:submit_button] || '<input type="submit" value="Upload">'
      protocol        = options[:secure] ? 'https' : 'http'
      cname           = options[:cname] || false

      # CNAME cannot use https and bucket mut be the same as the
      # Host headeraccording to S3 documentation.
      host = cname ? host = "http://#{bucket}/" : "#{protocol}://#{bucket}.s3.amazonaws.com/"

      options[:form] ||= {}
      options[:form][:id] ||= 'upload-form'
      options[:form][:class] ||= 'upload-form'

      policy = Base64.encode64(
        "{'expiration': '#{expiration_date}',
          'conditions': [
            {'bucket': '#{bucket}'},
            ['starts-with', '$key', '#{key}'],
            {'acl': '#{acl}'},
            {'success_action_redirect': '#{redirect}'},
            ['starts-with', '$Content-Type', '#{content_type}'],
            ['content-length-range', #{min_filesize}, #{max_filesize}]
          ]
        }").gsub(/\n|\r/, '')

        signature = b64_hmac_sha1(D2S3::S3Config.secret_access_key, policy)
        out = ""
        out << %(
          <form action="#{host}" method="post" enctype="multipart/form-data" id="#{options[:form][:id]}" class="#{options[:form][:class]}" style="#{options[:form][:style]}" \>
          <input type="hidden" name="key" value="#{key}/${filename}" \>
          <input type="hidden" name="AWSAccessKeyId" value="#{access_key_id}" \>
          <input type="hidden" name="acl" value="#{acl}" \>
          <input type="hidden" name="success_action_redirect" value="#{redirect}" \>
          <input type="hidden" name="policy" value="#{policy}" \>
          <input type="hidden" name="signature" value="#{signature}" \>
          <input type="hidden" name="Content-Type" value="#{content_type}" \>
          <input name="file" type="file" \>#{submit_button}
          </form>
        )
    end
  end
end

ActionView::Base.send(:include, D2S3::ViewHelpers)
