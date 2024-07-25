import { useState } from "react";
import PropTypes from 'prop-types';
import "./Referrals.css";
import SentRefs from "./SentRefs";
import ReceivedRefs from "./ReceivedRefs";
import CreateRefs from "./CreateReferral";

const Referrals = ({ role }) => {
  const [activeTab, setActiveTab] = useState("Referrals Sent");

  const renderContent = () => {
    switch (activeTab) {
      case "Referrals Sent":
        return <SentRefs role={role} />;
      case "Referrals Received":
        return <ReceivedRefs role={role} />;
      case "Create Referral":
        return <CreateRefs />;
      default:
        return null; // This case should never happen with the current setup
    }
  };

  return (
    <div className='Referrals'>
      <h2 className='ref-title'>MY REMUNERATION</h2>
      <div className='ref-underline'></div>
      <div className='tab-buttons'>
        <button
          onClick={() => setActiveTab("Referrals Sent")}
          className={activeTab === "Referrals Sent" ? "active" : ""}>
          Referrals Sent
        </button>
        <button
          onClick={() => setActiveTab("Referrals Received")}
          className={activeTab === "Referrals Received" ? "active" : ""}>
          Referrals Received
        </button>
        <button
          onClick={() => setActiveTab("Create Referral")}
          className={activeTab === "Create Referral" ? "active" : ""}>
          Create Referral
        </button>
      </div>
      <div className='tableHeader'>{activeTab}</div>
      <div className='tab-content'>{renderContent()}</div>
      <div className='tab-content-bottom'></div>
    </div>
  );
};

Referrals.propTypes = {
  role: PropTypes.string.isRequired,
};

export default Referrals;
