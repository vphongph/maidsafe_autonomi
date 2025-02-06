use crate::client::payment::Receipt;
use crate::client::{ClientEvent, UploadSummary};
use crate::files::UploadError;
use crate::Client;
use ant_evm::{Amount, AttoTokens};

impl Client {
    pub(crate) async fn process_upload_results(
        &self,
        uploads: Vec<(String, Result<usize, UploadError>)>,
        receipt: Receipt,
        skipped_payments_amount: usize,
    ) -> AttoTokens {
        let mut total_chunks_uploaded = 0;

        for (name, result) in uploads {
            match result {
                Ok(chunks_uploaded) => {
                    total_chunks_uploaded += chunks_uploaded;
                }
                Err(err) => {
                    error!("Error uploading file {name}: {err:?}");
                    #[cfg(feature = "loud")]
                    println!("Error uploading file {name}: {err:?}");
                }
            }
        }

        let tokens_spent = receipt
            .values()
            .map(|(_, cost)| cost.as_atto())
            .sum::<Amount>();

        // Reporting
        if let Some(channel) = self.client_event_sender.as_ref() {
            let summary = UploadSummary {
                records_paid: total_chunks_uploaded.saturating_sub(skipped_payments_amount),
                records_already_paid: skipped_payments_amount,
                tokens_spent,
            };
            if let Err(err) = channel.send(ClientEvent::UploadComplete(summary)).await {
                error!("Failed to send client event: {err:?}");
            }
        }

        AttoTokens::from_atto(tokens_spent)
    }
}
