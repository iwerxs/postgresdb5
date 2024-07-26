import { useEffect, useState } from 'react';
import axios from 'axios';
import '../styles.css';

const ReceivedRefs = () => {
  const [referrals, setReferrals] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReceivedReferrals = async () => {
      try {
        const response = await axios.get('http://localhost:8080/referrals-received', { withCredentials: true });
        setReferrals(response.data);
      } catch (error) {
        console.error('Error fetching received referrals:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchReceivedReferrals();
  }, []);

  const handleAction = async (referralRequestID, action) => {
    try {
      await axios.post(`http://localhost:8080/referral-request-action/${action}/${referralRequestID}`, {}, {
        withCredentials: true
      });
      alert(`Referral request ${action}ed successfully`);
      setReferrals(prevRequests =>
        prevRequests.map(request =>
          request.id === referralRequestID ? { ...request, status: action === 'approve' ? 'Approved' : 'Denied' } : request
        )
      );
    } catch (error) {
      console.error(`Error ${action}ing referral request:`, error);
      alert(`Failed to ${action} referral request`);
    }
  };

  if (loading) return <p>Loading...</p>;

  return (
    <div>
      <h2>Received Referrals</h2>
      <ul>
        {referrals.map(referral => (
          <li key={referral.id}>
            <strong>{referral.title}</strong>
            <p>{referral.content}</p>
            <p>Referee Client: {referral.referee_client}</p>
            <p>Referee Client Email: {referral.referee_client_email}</p>
            <p>Referrer: {referral.referrer_username}</p>
            <p>Status: {referral.status}</p>
            <p>Created At: {new Date(referral.created_at).toLocaleString()}</p>
            <button onClick={() => handleAction(referral.id, 'approve')}>Accept</button>
            <button onClick={() => handleAction(referral.id, 'deny')}>Deny</button>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default ReceivedRefs;
